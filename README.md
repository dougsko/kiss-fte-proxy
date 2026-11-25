# KISS FTE Proxy

A Python proxy that bridges a TCP KISS upstream (listening on 127.0.0.1:8001) to a Direwolf/TNC KISS port (127.0.0.1:8002).

Whatever raw bytes an upstream KISS client sends are accepted as-is — there is **no encryption** and no ciphertext. The proxy chunks the byte stream, prefixes each chunk with a 4-byte sequencing header, Base64-encodes it, wraps it in AX.25 7PLUS UI frames (`go_7+ ... stop_7+`), KISS-escapes the special bytes, and sends it out to the target KISS port. Every byte that comes in goes out in BBS format, unchanged.

## Features
- KISS ↔ TCP bridging
- Arbitrary binary input – pass-through of raw bytes, no AES/encryption
- Automatic chunking / reassembly (`MAX_PLAINTEXT_CHUNK = 110` bytes)
- AX.25 UI framing with KISS escaping/unescaping
- BBS-style control frame short-circuit (`SMALL_CTRL_THRESHOLD = 32` bytes)

## Quick Start
```bash
python3 kiss-bbs-fte.py
```

Configure the endpoints and call signs at the top of the script:
```python
APP_LISTEN_ADDR = ("127.0.0.1", 8001)   # Upstream app (TCP KISS)
TNC_TARGET_ADDR = ("127.0.0.1", 8002)   # Direwolf / TNC KISS port
SRC_CALL = "NODE1-1"
DST_CALL = "BBS-1"
```

Connect your upstream KISS application (or any app that speaks KISS over TCP) to `127.0.0.1:8001`. All frames it sends are encoded into BBS base64 AX.25 UI packets and forwarded to `127.0.0.1:8002`; replies are decoded back and sent to the upstream app.

## Requirements
- Python 3.8+
- Standard library only (no `cryptography` dependency)
