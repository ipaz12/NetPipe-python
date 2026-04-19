# NetPipe Wire Protocol Specification v1.0

This document describes the NetPipe wire protocol. Any client in any language
that implements this specification can communicate with a NetPipe server.

## 1. Transport

NetPipe supports two transport protocols: **TCP** and **UDP**.

TCP connections use a length-prefixed framing protocol to guarantee message
boundaries. UDP uses raw packets where each packet is one message.

Default port: **5000**.

## 2. TCP Frame Format

Every TCP message is wrapped in a frame:

```
[4 bytes: length][1 byte: flags][N bytes: body]
```

- **length**: Big-endian unsigned 32-bit integer. Value = 1 + len(body).
  This counts the flags byte plus the body. It does NOT include the 4-byte
  length field itself.
- **flags**: Single byte. Bit field defining message type (see §4).
- **body**: Variable-length payload. May be empty (e.g. ping/pong).

Maximum frame body size: **16,777,216 bytes** (16 MB).

### Example: sending "hello" (5 bytes)

```
length = 1 (flags) + 5 (body) = 6
hex: 00 00 00 06 | 00 | 68 65 6C 6C 6F
     └─ length ─┘  flags  └── "hello" ──┘
```

## 3. UDP Packet Format

Each UDP packet is a single message with no length prefix:

```
[1 byte: flags][N bytes: body]
```

UDP packets are inherently bounded - each packet IS a message boundary.
Maximum practical payload: **65,507 bytes**.

## 4. Flags Byte

The flags byte is a bit field. Bits can be combined but in practice only one
flag is set per message.

| Bit | Value  | Name       | Direction        | Description                        |
|-----|--------|------------|------------------|------------------------------------|
| 0   | `0x01` | encrypted  | client ↔ server  | Body is AES-256-GCM encrypted      |
| 1   | `0x02` | stream     | client ↔ server  | Body is a stream chunk             |
| 2   | `0x04` | ping       | server → client  | Heartbeat ping, empty body         |
| 3   | `0x08` | pong       | client → server  | Heartbeat response, empty body     |
| 4   | `0x10` | reject     | server → client  | Rejection, body is UTF-8 reason    |
| 5   | `0x20` | handshake  | peer ↔ peer      | P2P DH key exchange                |
| 6-7 |        | reserved   |                  | Must be zero                       |

A flags byte of `0x00` is a plain data message.

## 5. Encryption (flag 0x01)

When the encrypted flag is set, the body contains AES-256-GCM encrypted data:

```
body = [12 bytes: nonce][ciphertext + 16 bytes: GCM authentication tag]
```

### Key Derivation

The encryption key can be any string. It is derived to exactly 32 bytes using
SHA-256:

```
key_bytes = SHA256(key_string_as_utf8_bytes)
```

### Encryption Process

1. Generate 12 random bytes for the nonce.
2. Create AES-256-GCM cipher with the derived key.
3. Encrypt the plaintext with the nonce, producing ciphertext + 16-byte auth tag.
4. Prepend the nonce to the ciphertext.

### Decryption Process

1. Extract the first 12 bytes as the nonce.
2. The remainder is ciphertext + auth tag.
3. Decrypt with AES-256-GCM using the derived key and nonce.
4. If the auth tag does not validate, the message is corrupt or tampered - discard.

## 6. Streaming (flag 0x02)

For large payloads, data is split into chunks. Each chunk is sent as a separate
frame with the stream flag set. The body of each chunk frame contains:

```
body = [16 bytes: stream UUID][4 bytes: chunk index][4 bytes: total chunks][N bytes: chunk data]
```

- **stream UUID**: 16-byte binary UUID identifying this stream transfer.
  All chunks in the same stream share the same UUID.
- **chunk index**: Big-endian unsigned 32-bit integer. Zero-indexed.
- **total chunks**: Big-endian unsigned 32-bit integer. Total number of chunks.
- **chunk data**: The payload bytes for this chunk.

### Reassembly Rules

1. Buffer chunks keyed by stream UUID.
2. Once all chunks (0 through total-1) have arrived, concatenate in order.
3. Deliver the reassembled payload to the application.
4. Discard chunks where `index >= total` or `total == 0`.
5. Discard chunks where `total` does not match previous chunks for the same stream.
6. Duplicate chunks (same stream + same index) should be ignored.

### Recommended Limits

- Maximum pending incomplete streams: **256**.
- Incomplete stream timeout: **60 seconds**.
- Default chunk size: **65,536 bytes** (64 KB).

## 7. Heartbeat (flags 0x04 / 0x08)

The server periodically sends **ping** frames (flag `0x04`) with an empty body.
The client must respond with a **pong** frame (flag `0x08`) with an empty body.

If the client does not respond within the server's configured timeout, the
server disconnects the client.

Clients must handle ping automatically - no developer action required.

## 8. Rejection (flag 0x10)

When the server cannot accept a connection (at capacity, IP limit, etc.), it
sends a **reject** frame before closing:

```
flags = 0x10
body  = UTF-8 encoded reason string (e.g. "server full")
```

The client should fire a rejection callback, then expect the connection to close.

## 9. P2P Handshake (flag 0x20)

In peer-to-peer mode, every connection begins with a Diffie-Hellman key exchange
using X25519 (Curve25519). The handshake body is:

```
body = [32 bytes: X25519 public key][16 bytes: peer UUID binary]
```

### Handshake Sequence

1. **Initiator** connects via TCP and sends a `flagHandshake` frame with its
   ephemeral X25519 public key and UUID.
2. **Listener** generates its own ephemeral key pair and responds with a
   `flagHandshake` frame containing its public key and UUID.
3. Both sides compute: `sharedSecret = X25519(myPrivateKey, theirPublicKey)`
4. Both derive the AES key: `aesKey = SHA-256(sharedSecret)`
5. All subsequent frames are AES-256-GCM encrypted with this key.

Each peer pair in a mesh performs its own independent handshake. Compromising
one connection does not compromise others - each has a unique shared secret.

The handshake flag must only appear as the first frame on a new connection.
Any handshake frames received after the initial exchange must be ignored.

## 10. Client Identification

The server assigns each connected client a UUID (v4) at connection time. This
UUID is internal to the server - it is not transmitted to the client over the
wire. The client does not need to identify itself.

## 11. Byte Order

All multi-byte integers in the protocol are **big-endian** (network byte order).

## 12. Implementation Checklist

A conforming client implementation must:

- [ ] Frame TCP messages with `[4B length][1B flags][NB body]`
- [ ] Handle `flags = 0x00` as plain data
- [ ] Handle `flags = 0x01` as AES-256-GCM encrypted (decrypt before delivery)
- [ ] Handle `flags = 0x02` as stream chunks (buffer and reassemble)
- [ ] Respond to `flags = 0x04` (ping) with `flags = 0x08` (pong)
- [ ] Handle `flags = 0x10` (reject) gracefully
- [ ] Support SHA-256 key derivation for encryption
- [ ] Enforce 16 MB maximum message size
- [ ] Use big-endian byte order for all integers
- [ ] (P2P) Implement X25519 DH handshake on connection
- [ ] (P2P) Auto-encrypt all post-handshake frames with derived AES-256 key
