"""
NetPipe stream reassembly - buffers incoming chunks and reassembles.

Matches the Go streamBuffer: max 256 pending streams, 60s timeout,
validates index/total, ignores duplicates.
"""

import time
import uuid as _uuid
import struct
import threading

from netpipe.protocol import STREAM_HEADER_SIZE, DEFAULT_CHUNK_SIZE

MAX_PENDING_STREAMS = 256
STREAM_TIMEOUT = 60.0  # seconds


class _StreamState:
    __slots__ = ("total", "received", "chunks", "created_at")

    def __init__(self, total: int):
        self.total = total
        self.received = 0
        self.chunks: dict[int, bytes] = {}
        self.created_at = time.monotonic()


class StreamBuffer:
    """Thread-safe stream reassembly buffer."""

    def __init__(self):
        self._lock = threading.Lock()
        self._streams: dict[bytes, _StreamState] = {}

    def add_chunk(self, stream_id: bytes, index: int, total: int, data: bytes):
        """
        Add a chunk. Returns the fully reassembled bytes if this was the
        last missing chunk, otherwise returns None.
        """
        if total == 0 or index >= total:
            return None

        with self._lock:
            # clean up expired streams
            now = time.monotonic()
            expired = [
                sid for sid, s in self._streams.items()
                if now - s.created_at > STREAM_TIMEOUT
            ]
            for sid in expired:
                del self._streams[sid]

            state = self._streams.get(stream_id)
            if state is None:
                # reject if too many pending
                if len(self._streams) >= MAX_PENDING_STREAMS:
                    return None

                state = _StreamState(total)
                self._streams[stream_id] = state

            # validate total consistency
            if state.total != total:
                return None

            # ignore duplicates
            if index in state.chunks:
                return None

            state.chunks[index] = data
            state.received += 1

            if state.received < state.total:
                return None

            # reassemble in order
            assembled = b"".join(state.chunks[i] for i in range(state.total))
            del self._streams[stream_id]
            return assembled


def chunk_data(data: bytes, chunk_size: int = DEFAULT_CHUNK_SIZE):
    """
    Split data into stream chunks ready to send.
    Yields (stream_id_bytes, index, total, chunk_bytes) tuples.
    """
    stream_id = _uuid.uuid4().bytes  # 16 bytes
    total = max(1, (len(data) + chunk_size - 1) // chunk_size)

    for i in range(total):
        start = i * chunk_size
        end = min(start + chunk_size, len(data))
        yield stream_id, i, total, data[start:end]
