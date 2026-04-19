"""
NetPipe Python Client - connects to a Go NetPipe server.

Usage:
    from netpipe import Client

    client = Client(host="127.0.0.1", port=5000)

    @client.on_data
    def handle(data):
        print("received:", data.decode())

    client.connect()
    client.send(b"hello from python")
    client.start()  # blocking listen loop (or use start_async for a thread)
"""

import socket
import threading
import time

from netpipe.protocol import (
    FLAG_ENCRYPTED, FLAG_STREAM, FLAG_PING, FLAG_PONG, FLAG_REJECT,
    DEFAULT_CHUNK_SIZE,
    encode_frame, decode_frame,
    encode_udp_packet, decode_udp_packet,
    encode_stream_header, decode_stream_header,
)
from netpipe.crypto import encrypt, decrypt
from netpipe.stream import StreamBuffer, chunk_data


class Client:
    """
    Connects to a NetPipe server and exchanges raw data.

    Args:
        host: Server address. Defaults to "127.0.0.1".
        port: Server port. Defaults to 5000.
        protocol: "tcp" (default) or "udp".
        encryption_key: Optional key for auto-decrypting incoming encrypted messages.
        chunk_size: Stream chunk size in bytes. Defaults to 64 KB.
        auto_reconnect: Automatically reconnect on disconnect. Defaults to False.
        reconnect_interval: Seconds between reconnect attempts. Defaults to 2.
        max_reconnect_attempts: 0 = infinite. Defaults to 0.
    """

    def __init__(
        self,
        host: str = "127.0.0.1",
        port: int = 5000,
        protocol: str = "tcp",
        encryption_key: str = "",
        chunk_size: int = DEFAULT_CHUNK_SIZE,
        auto_reconnect: bool = False,
        reconnect_interval: float = 2.0,
        max_reconnect_attempts: int = 0,
    ):
        self._host = host
        self._port = port
        self._protocol = protocol
        self._encryption_key = encryption_key
        self._chunk_size = chunk_size
        self._auto_reconnect = auto_reconnect
        self._reconnect_interval = reconnect_interval
        self._max_reconnect_attempts = max_reconnect_attempts

        self._sock: socket.socket | None = None
        self._connected = False
        self._streams = StreamBuffer()
        self._lock = threading.Lock()  # protects writes for thread safety

        # callbacks
        self._on_data = None
        self._on_disconnect = None
        self._on_stream = None
        self._on_reject = None

    # -----------------------------------------------------------------------
    # Event registration - decorator style and method style both work
    # -----------------------------------------------------------------------

    def on_data(self, fn):
        """Register callback for incoming data. Works as a decorator or method."""
        self._on_data = fn
        return fn

    def on_disconnect(self, fn):
        """Register callback for disconnection. Works as a decorator or method."""
        self._on_disconnect = fn
        return fn

    def on_stream(self, fn):
        """Register callback for completed stream transfers. Works as a decorator or method."""
        self._on_stream = fn
        return fn

    def on_reject(self, fn):
        """Register callback for server rejection. Receives reason string."""
        self._on_reject = fn
        return fn

    # -----------------------------------------------------------------------
    # Lifecycle
    # -----------------------------------------------------------------------

    def connect(self):
        """Connect to the server. Raises ConnectionError on failure."""
        if self._protocol == "udp":
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._sock.connect((self._host, self._port))
        else:
            self._sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            self._sock.connect((self._host, self._port))

        self._connected = True

    def disconnect(self):
        """Close the connection cleanly."""
        self._connected = False
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
            self._sock = None

    @property
    def is_connected(self) -> bool:
        """True if the client has an active connection."""
        return self._connected and self._sock is not None

    # -----------------------------------------------------------------------
    # Send methods
    # -----------------------------------------------------------------------

    def send(self, data: bytes):
        """Send raw bytes to the server."""
        self._send_frame(0x00, data)

    def send_encrypted(self, data: bytes, key: str):
        """Send AES-256-GCM encrypted bytes. Key can be any string."""
        ciphertext = encrypt(data, key)
        self._send_frame(FLAG_ENCRYPTED, ciphertext)

    def send_stream(self, data: bytes, chunk_size: int = 0):
        """Send large data as a chunked stream. Server receives it via on_stream."""
        cs = chunk_size if chunk_size > 0 else self._chunk_size
        for stream_id, index, total, chunk in chunk_data(data, cs):
            header = encode_stream_header(stream_id, index, total)
            self._send_frame(FLAG_STREAM, header + chunk)

    # -----------------------------------------------------------------------
    # Listen
    # -----------------------------------------------------------------------

    def start(self):
        """
        Start the blocking listen loop. Call this after connect() and
        registering callbacks. Blocks until disconnect.

        For a non-blocking version, use start_async().
        """
        if not self._sock:
            return

        if self._protocol == "udp":
            self._listen_udp()
        else:
            self._read_loop()

        # connection dropped
        if self._auto_reconnect:
            self._reconnect_loop()
        elif self._on_disconnect:
            self._on_disconnect()

    def start_async(self) -> threading.Thread:
        """
        Start the listen loop in a background daemon thread.
        Returns the thread so you can join it if needed.

        Usage:
            client.connect()
            client.start_async()
            # ... do other stuff ...
            client.send(b"hello")
        """
        t = threading.Thread(target=self.start, daemon=True)
        t.start()
        return t

    # -----------------------------------------------------------------------
    # Internal - frame send
    # -----------------------------------------------------------------------

    def _send_frame(self, flags: int, body: bytes):
        """Send a framed message, thread-safe."""
        if not self._sock:
            raise ConnectionError("netpipe: not connected")

        if self._protocol == "udp":
            packet = encode_udp_packet(flags, body)
            self._sock.send(packet)
        else:
            frame = encode_frame(flags, body)
            with self._lock:
                self._sock.sendall(frame)

    def _send_pong(self):
        """Respond to server ping with pong."""
        try:
            self._send_frame(FLAG_PONG, b"")
        except (OSError, ConnectionError):
            pass  # connection already gone

    # -----------------------------------------------------------------------
    # Internal - TCP read loop
    # -----------------------------------------------------------------------

    def _read_loop(self):
        """TCP read loop. Returns when the connection drops."""
        while self._connected and self._sock:
            try:
                flags, body = decode_frame(self._sock)
            except (ConnectionError, OSError, ValueError):
                break

            # ping - auto-pong
            if flags & FLAG_PING:
                self._send_pong()
                continue

            # pong - ignore (server shouldn't send these)
            if flags & FLAG_PONG:
                continue

            # reject - fire callback and break
            if flags & FLAG_REJECT:
                if self._on_reject:
                    self._on_reject(body.decode("utf-8", errors="replace"))
                break

            # stream chunk - reassemble
            if flags & FLAG_STREAM:
                try:
                    stream_id, index, total, chunk = decode_stream_header(body)
                except ValueError:
                    continue

                assembled = self._streams.add_chunk(stream_id, index, total, chunk)
                if assembled is not None and self._on_stream:
                    self._on_stream(assembled)
                continue

            # encrypted - decrypt first
            if flags & FLAG_ENCRYPTED:
                if self._encryption_key:
                    try:
                        body = decrypt(body, self._encryption_key)
                    except Exception:
                        continue  # bad key or corrupt - skip

            # fire on_data
            if self._on_data:
                self._on_data(body)

        self._connected = False
        self._sock = None

    # -----------------------------------------------------------------------
    # Internal - UDP read loop
    # -----------------------------------------------------------------------

    def _listen_udp(self):
        """UDP receive loop. Returns when the connection drops."""
        while self._connected and self._sock:
            try:
                data = self._sock.recv(65507)
            except (OSError, ConnectionError):
                break

            if len(data) < 1:
                continue

            try:
                flags, body = decode_udp_packet(data)
            except ValueError:
                continue

            # ping - auto-pong
            if flags & FLAG_PING:
                self._send_pong()
                continue

            if flags & FLAG_PONG:
                continue

            if flags & FLAG_REJECT:
                if self._on_reject:
                    self._on_reject(body.decode("utf-8", errors="replace"))
                break

            # stream chunk
            if flags & FLAG_STREAM:
                try:
                    stream_id, index, total, chunk = decode_stream_header(body)
                except ValueError:
                    continue
                assembled = self._streams.add_chunk(stream_id, index, total, chunk)
                if assembled is not None and self._on_stream:
                    self._on_stream(assembled)
                continue

            # encrypted
            if flags & FLAG_ENCRYPTED:
                if self._encryption_key:
                    try:
                        body = decrypt(body, self._encryption_key)
                    except Exception:
                        continue

            if self._on_data:
                self._on_data(body)

        self._connected = False
        self._sock = None

    # -----------------------------------------------------------------------
    # Internal - auto-reconnect (iterative, not recursive)
    # -----------------------------------------------------------------------

    def _reconnect_loop(self):
        """Iterative reconnect with backoff. Never recurses."""
        attempt = 0
        while True:
            if 0 < self._max_reconnect_attempts <= attempt:
                if self._on_disconnect:
                    self._on_disconnect()
                return

            time.sleep(self._reconnect_interval)
            attempt += 1

            try:
                self.connect()
            except (OSError, ConnectionError):
                continue

            # reconnected - reset counter and re-enter read loop
            attempt = 0
            if self._protocol == "udp":
                self._listen_udp()
            else:
                self._read_loop()

            # read loop returned - disconnected again, loop back to retry
