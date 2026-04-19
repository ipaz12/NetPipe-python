"""Tests for the NetPipe Python client internals."""

import struct
import unittest
import uuid

from netpipe.protocol import (
    FLAG_ENCRYPTED, FLAG_STREAM, FLAG_PING, FLAG_PONG, FLAG_REJECT,
    encode_frame, encode_udp_packet,
    decode_stream_header, encode_stream_header,
    STREAM_HEADER_SIZE, MAX_MESSAGE_SIZE,
)
from netpipe.crypto import encrypt, decrypt
from netpipe.stream import StreamBuffer, chunk_data


class TestProtocolEncoding(unittest.TestCase):
    """Test that frame encoding matches Go wire format byte-for-byte."""

    def test_plain_frame(self):
        frame = encode_frame(0x00, b"hello")
        # [4B length=6][1B flags=0x00][5B "hello"]
        expected_length = struct.pack(">I", 6)
        self.assertEqual(frame[:4], expected_length)
        self.assertEqual(frame[4], 0x00)
        self.assertEqual(frame[5:], b"hello")

    def test_encrypted_flag(self):
        frame = encode_frame(FLAG_ENCRYPTED, b"ciphertext")
        self.assertEqual(frame[4], FLAG_ENCRYPTED)

    def test_stream_flag(self):
        frame = encode_frame(FLAG_STREAM, b"streamdata")
        self.assertEqual(frame[4], FLAG_STREAM)

    def test_ping_frame(self):
        frame = encode_frame(FLAG_PING, b"")
        # length = 1 (flags) + 0 (empty body) = 1
        expected_length = struct.pack(">I", 1)
        self.assertEqual(frame[:4], expected_length)
        self.assertEqual(frame[4], FLAG_PING)
        self.assertEqual(len(frame), 5)

    def test_reject_frame(self):
        reason = b"server full"
        frame = encode_frame(FLAG_REJECT, reason)
        self.assertEqual(frame[4], FLAG_REJECT)
        self.assertEqual(frame[5:], reason)

    def test_udp_packet(self):
        packet = encode_udp_packet(0x00, b"hello")
        self.assertEqual(packet[0], 0x00)
        self.assertEqual(packet[1:], b"hello")

    def test_oversize_rejected(self):
        with self.assertRaises(ValueError):
            encode_frame(0x00, b"x" * (MAX_MESSAGE_SIZE + 1))

    def test_length_includes_flags_byte(self):
        """The length field counts the flags byte + body, not just body."""
        frame = encode_frame(0x00, b"abc")
        length = struct.unpack(">I", frame[:4])[0]
        self.assertEqual(length, 4)  # 1 (flags) + 3 (body)


class TestStreamHeader(unittest.TestCase):
    """Test stream header encoding/decoding."""

    def test_round_trip(self):
        stream_id = uuid.uuid4().bytes
        header = encode_stream_header(stream_id, 3, 10)
        body = header + b"chunk data here"

        sid, index, total, chunk = decode_stream_header(body)
        self.assertEqual(sid, stream_id)
        self.assertEqual(index, 3)
        self.assertEqual(total, 10)
        self.assertEqual(chunk, b"chunk data here")

    def test_too_short(self):
        with self.assertRaises(ValueError):
            decode_stream_header(b"short")


class TestCrypto(unittest.TestCase):
    """Test AES-256-GCM encryption matches Go output format."""

    def test_round_trip(self):
        plaintext = b"hello encrypted world"
        key = "my-secret-key"
        ct = encrypt(plaintext, key)
        pt = decrypt(ct, key)
        self.assertEqual(pt, plaintext)

    def test_wrong_key(self):
        ct = encrypt(b"secret", "correct-key")
        with self.assertRaises(Exception):
            decrypt(ct, "wrong-key")

    def test_unique_nonces(self):
        ct1 = encrypt(b"same", "same-key")
        ct2 = encrypt(b"same", "same-key")
        self.assertNotEqual(ct1, ct2)

    def test_any_key_length(self):
        for key in ["a", "short", "a-much-longer-key-that-exceeds-32-bytes-easily"]:
            ct = encrypt(b"test", key)
            pt = decrypt(ct, key)
            self.assertEqual(pt, b"test")

    def test_empty_plaintext(self):
        ct = encrypt(b"", "key")
        pt = decrypt(ct, "key")
        self.assertEqual(pt, b"")

    def test_nonce_is_12_bytes(self):
        ct = encrypt(b"data", "key")
        # first 12 bytes are nonce, rest is ciphertext + 16B tag
        self.assertGreater(len(ct), 12 + 16)


class TestStreamBuffer(unittest.TestCase):
    """Test stream reassembly."""

    def test_single_chunk(self):
        buf = StreamBuffer()
        result = buf.add_chunk(b"s" * 16, 0, 1, b"complete")
        self.assertEqual(result, b"complete")

    def test_multi_chunk_reassembly(self):
        buf = StreamBuffer()
        sid = b"stream-id-16byt"
        self.assertIsNone(buf.add_chunk(sid, 0, 3, b"aaa"))
        self.assertIsNone(buf.add_chunk(sid, 1, 3, b"bbb"))
        result = buf.add_chunk(sid, 2, 3, b"ccc")
        self.assertEqual(result, b"aaabbbccc")

    def test_out_of_order(self):
        buf = StreamBuffer()
        sid = b"stream-id-16byt"
        self.assertIsNone(buf.add_chunk(sid, 2, 3, b"ccc"))
        self.assertIsNone(buf.add_chunk(sid, 0, 3, b"aaa"))
        result = buf.add_chunk(sid, 1, 3, b"bbb")
        self.assertEqual(result, b"aaabbbccc")

    def test_duplicate_ignored(self):
        buf = StreamBuffer()
        sid = b"stream-id-16byt"
        buf.add_chunk(sid, 0, 2, b"aaa")
        result = buf.add_chunk(sid, 0, 2, b"aaa")  # duplicate
        self.assertIsNone(result)

    def test_invalid_index(self):
        buf = StreamBuffer()
        result = buf.add_chunk(b"s" * 16, 5, 3, b"bad")  # index >= total
        self.assertIsNone(result)

    def test_zero_total(self):
        buf = StreamBuffer()
        result = buf.add_chunk(b"s" * 16, 0, 0, b"bad")
        self.assertIsNone(result)

    def test_inconsistent_total(self):
        buf = StreamBuffer()
        sid = b"stream-id-16byt"
        buf.add_chunk(sid, 0, 3, b"aaa")
        result = buf.add_chunk(sid, 1, 5, b"bbb")  # different total
        self.assertIsNone(result)

    def test_cleanup_after_completion(self):
        buf = StreamBuffer()
        sid = b"stream-id-16byt"
        buf.add_chunk(sid, 0, 1, b"data")
        # stream should be cleaned up
        self.assertNotIn(sid, buf._streams)


class TestChunkData(unittest.TestCase):
    """Test the chunk_data generator."""

    def test_small_payload(self):
        chunks = list(chunk_data(b"tiny", chunk_size=1024))
        self.assertEqual(len(chunks), 1)
        sid, index, total, data = chunks[0]
        self.assertEqual(len(sid), 16)
        self.assertEqual(index, 0)
        self.assertEqual(total, 1)
        self.assertEqual(data, b"tiny")

    def test_exact_chunks(self):
        payload = b"a" * 100
        chunks = list(chunk_data(payload, chunk_size=50))
        self.assertEqual(len(chunks), 2)
        self.assertEqual(chunks[0][3], b"a" * 50)
        self.assertEqual(chunks[1][3], b"a" * 50)

    def test_reassembly(self):
        payload = b"hello world this is a test of streaming"
        chunks = list(chunk_data(payload, chunk_size=10))
        buf = StreamBuffer()
        result = None
        for sid, idx, total, data in chunks:
            result = buf.add_chunk(sid, idx, total, data)
        self.assertEqual(result, payload)


if __name__ == "__main__":
    unittest.main()
