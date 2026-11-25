# KISS FTE Proxy

A Python proxy that bridges a Reticulum/TCP KISS upstream (listening on 127.0.0.1:8001) to a Direwolf/TNC KISS port (127.0.0.1:8002).  
Frames are encrypted with **AES-256-GCM** (shared 32-byte key) and fragmented into AX.25 UI frames using 7PLUS blocking for reliable transport over packet radio.

## Features
- KISS ↔ TCP bridging
- AES-256-GCM authenticated encryption
- Automatic chunking / reassembly (`MAX_PLAINTEXT_CHUNK = 110` bytes)
- AX.25 UI framing with KISS escaping/unescaping
- BBS-style control frame short-circuit (`SMALL_CTRL_THRESHOLD = 32` bytes)

## Quick Start
```bash
pip install cryptography
python3 kiss-bbs-fte.py
```

Configure the endpoints and shared key at the top of the script:
```python
APP_LISTEN_ADDR = ("127.0.0.1", 8001)   # Upstream app (Reticulum / TCP KISS)
TNC_TARGET_ADDR = ("127.0.0.1", 8002)   # Direwolf / TNC KISS port
SRC_CALL = "NODE1-1"
DST_CALL = "BBS-1"
AES_KEY = bytes.fromhex("...")          # 32-byte hex key (must match on both ends)
```

## Requirements
- Python 3.8+
- `cryptography` package
