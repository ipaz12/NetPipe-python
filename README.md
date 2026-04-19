# netpipe-client

Python client for [NetPipe](https://github.com/ipaz12/NetPipe) - a general-purpose TCP/UDP data transport library written in Go.

## Install

```bash
pip install netpipe-client
```

## Quick Start

```python
from netpipe import Client

client = Client(host="127.0.0.1", port=5000)

@client.on_data
def handle(data):
    print("received:", data.decode())

@client.on_disconnect
def disconnected():
    print("server disconnected")

client.connect()
client.send(b"hello from python")
client.start()  # blocks - listens for incoming data
```

## Non-blocking

```python
client.connect()
client.start_async()  # runs in a background thread

client.send(b"hello")
client.send(b"world")
```

## Encrypted Messages

```python
# send encrypted - server decrypts automatically if it has the same key
client.send_encrypted(b"sensitive data", "my-secret-key")

# auto-decrypt incoming encrypted messages from the server
client = Client(encryption_key="my-secret-key")
```

## Large Data Streaming

```python
# send a 10 MB file - auto-chunked, server receives it as one payload
with open("bigfile.bin", "rb") as f:
    client.send_stream(f.read())

# receive streams
@client.on_stream
def handle_stream(data):
    print(f"received stream: {len(data)} bytes")
```

## UDP

```python
client = Client(protocol="udp")
```

## Auto-Reconnect

```python
client = Client(auto_reconnect=True, reconnect_interval=3.0, max_reconnect_attempts=10)
```

## Server Rejection

```python
@client.on_reject
def rejected(reason):
    print(f"server rejected us: {reason}")
```

## API Reference

### Constructor

```python
Client(
    host="127.0.0.1",
    port=5000,
    protocol="tcp",           # "tcp" or "udp"
    encryption_key="",        # auto-decrypt incoming encrypted messages
    chunk_size=65536,          # stream chunk size
    auto_reconnect=False,
    reconnect_interval=2.0,
    max_reconnect_attempts=0,  # 0 = infinite
)
```

### Methods

| Method | Description |
|--------|-------------|
| `connect()` | Connect to the server |
| `disconnect()` | Close the connection |
| `send(data)` | Send raw bytes |
| `send_encrypted(data, key)` | Send AES-256-GCM encrypted bytes |
| `send_stream(data)` | Send large data as a chunked stream |
| `start()` | Blocking listen loop |
| `start_async()` | Listen in a background thread, returns the thread |
| `is_connected` | Property - True if connected |

### Callbacks

| Callback | Signature | Description |
|----------|-----------|-------------|
| `on_data` | `fn(data: bytes)` | Incoming data from server |
| `on_disconnect` | `fn()` | Server disconnected |
| `on_stream` | `fn(data: bytes)` | Completed stream transfer |
| `on_reject` | `fn(reason: str)` | Server rejected the connection |

All callbacks work as decorators or as methods:

```python
# decorator style
@client.on_data
def handle(data): ...

# method style
client.on_data(my_handler)
```

## Protocol

See [PROTOCOL.md](PROTOCOL.md) for the full wire protocol specification.

## Requirements

- Python 3.10+
- `cryptography` package (for AES-256-GCM)
- A running NetPipe Go server
