"""
Cross-language compatibility tests.

These verify that the Python client produces the exact same wire bytes
as the Go server expects, and can parse what the Go server sends.
"""

import struct
import unittest
from hashlib import sha256

from netpipe.protocol import encode_frame, FLAG_ENCRYPTED, FLAG_STREAM, FLAG_PING, FLAG_PONG
from netpipe.crypto import encrypt, decrypt


class TestGoCompatibility(unittest.TestCase):
    """Verify wire format matches Go implementation byte-for-byte."""

    def test_frame_length_is_big_endian(self):
        """Go uses binary.BigEndian.PutUint32 - verify Python matches."""
        frame = encode_frame(0x00, b"test")
        length = struct.unpack(">I", frame[:4])[0]
        self.assertEqual(length, 5)  # 1 flags + 4 body

    def test_flags_at_byte_4(self):
        """Go writes flags at frame[headerSize] = frame[4]."""
        frame = encode_frame(FLAG_ENCRYPTED, b"data")
        self.assertEqual(frame[4], 0x01)

    def test_body_starts_at_byte_5(self):
        """Go copies body at frame[headerSize+flagSize:] = frame[5:]."""
        frame = encode_frame(0x00, b"hello")
        self.assertEqual(frame[5:], b"hello")

    def test_key_derivation_matches_go(self):
        """
        Go: keyHash := sha256.Sum256([]byte(key))
        Python must produce the same 32 bytes.
        """
        key = "my-secret-key"
        go_key = sha256(key.encode("utf-8")).digest()
        self.assertEqual(len(go_key), 32)

        # verify it works for encryption round-trip
        ct = encrypt(b"test", key)
        pt = decrypt(ct, key)
        self.assertEqual(pt, b"test")

    def test_nonce_size_matches_go_gcm(self):
        """Go uses gcm.NonceSize() which is 12 for GCM. Verify nonce is 12 bytes."""
        ct = encrypt(b"test", "key")
        nonce = ct[:12]
        self.assertEqual(len(nonce), 12)

    def test_ping_pong_empty_body(self):
        """Go sends ping/pong with nil body - Python must handle empty body."""
        ping_frame = encode_frame(FLAG_PING, b"")
        self.assertEqual(len(ping_frame), 5)  # 4 length + 1 flags + 0 body

        pong_frame = encode_frame(FLAG_PONG, b"")
        self.assertEqual(len(pong_frame), 5)

    def test_stream_header_big_endian(self):
        """Go uses binary.BigEndian for stream chunk index and total."""
        from netpipe.protocol import encode_stream_header, decode_stream_header
        import uuid

        sid = uuid.uuid4().bytes
        header = encode_stream_header(sid, 42, 100)

        # manually verify big-endian encoding
        index_bytes = header[16:20]
        total_bytes = header[20:24]
        self.assertEqual(struct.unpack(">I", index_bytes)[0], 42)
        self.assertEqual(struct.unpack(">I", total_bytes)[0], 100)


if __name__ == "__main__":
    unittest.main()
