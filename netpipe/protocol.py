"""
NetPipe wire protocol - matches the Go server byte-for-byte.

TCP frame:  [4B big-endian uint32 length][1B flags][NB body]
            length = 1 (flags) + len(body)

UDP packet: [1B flags][NB body]

Flags:
    0x01  encrypted   - body is [12B nonce][AES-GCM ciphertext + tag]
    0x02  stream      - body is [16B UUID][4B index][4B total][chunk data]
    0x04  ping        - server → client heartbeat, empty body
    0x08  pong        - client → server heartbeat response, empty body
    0x10  reject      - server → client rejection, body is UTF-8 reason
"""

import struct

# ---------------------------------------------------------------------------
# Flag constants - must match Go constants exactly
# ---------------------------------------------------------------------------

FLAG_ENCRYPTED = 0x01
FLAG_STREAM = 0x02
FLAG_PING = 0x04
FLAG_PONG = 0x08
FLAG_REJECT = 0x10

# Maximum message size (16 MB) - same as Go MaxMessageSize
MAX_MESSAGE_SIZE = 16 * 1024 * 1024

# Stream header: 16 bytes UUID + 4 bytes index + 4 bytes total
STREAM_HEADER_SIZE = 24

# Default stream chunk size (64 KB)
DEFAULT_CHUNK_SIZE = 64 * 1024


# ---------------------------------------------------------------------------
# Frame encoding
# ---------------------------------------------------------------------------

def encode_frame(flags: int, body: bytes) -> bytes:
    """Encode a TCP frame: [4B length][1B flags][NB body]."""
    if len(body) > MAX_MESSAGE_SIZE:
        raise ValueError(f"message too large ({len(body)} bytes, max {MAX_MESSAGE_SIZE})")
    length = 1 + len(body)  # flags byte + body
    return struct.pack(">I", length) + bytes([flags]) + body


def encode_udp_packet(flags: int, body: bytes) -> bytes:
    """Encode a UDP packet: [1B flags][NB body]."""
    return bytes([flags]) + body


# ---------------------------------------------------------------------------
# Frame decoding
# ---------------------------------------------------------------------------

def read_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from a socket. Raises ConnectionError on disconnect."""
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("netpipe: connection closed")
        buf.extend(chunk)
    return bytes(buf)


def decode_frame(sock) -> tuple:
    """
    Read one complete TCP frame from the socket.
    Returns (flags: int, body: bytes).
    Blocks until a complete frame arrives.
    """
    # 1. read 4-byte length header
    header = read_exact(sock, 4)
    length = struct.unpack(">I", header)[0]

    if length == 0:
        return 0, b""

    if length > MAX_MESSAGE_SIZE:
        raise ValueError(f"netpipe: incoming message too large ({length} bytes)")

    # 2. read flags + body
    payload = read_exact(sock, length)
    flags = payload[0]
    body = payload[1:]

    return flags, body


def decode_udp_packet(data: bytes) -> tuple:
    """
    Decode a UDP packet: [1B flags][NB body].
    Returns (flags: int, body: bytes).
    """
    if len(data) < 1:
        raise ValueError("netpipe: UDP packet too short")
    return data[0], data[1:]


# ---------------------------------------------------------------------------
# Stream header encoding/decoding
# ---------------------------------------------------------------------------

def encode_stream_header(stream_id: bytes, index: int, total: int) -> bytes:
    """Encode stream chunk header: [16B UUID][4B index][4B total]."""
    return stream_id + struct.pack(">II", index, total)


def decode_stream_header(body: bytes) -> tuple:
    """
    Decode stream chunk header from body.
    Returns (stream_id: bytes, index: int, total: int, chunk_data: bytes).
    """
    if len(body) < STREAM_HEADER_SIZE:
        raise ValueError(f"netpipe: stream body too short ({len(body)} bytes)")

    stream_id = body[:16]
    index, total = struct.unpack(">II", body[16:24])
    chunk_data = body[24:]

    return stream_id, index, total, chunk_data
