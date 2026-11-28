# KISS FTE Proxy

A Python proxy that bridges a TCP KISS upstream (default `127.0.0.1:8001`) to a Direwolf/TNC KISS port (default `127.0.0.1:8002`). It applies **observation-based FTE encoding** (format-transforming encryption) to payloads and wraps them in plausible cover traffic (BBS/APRS, HTTP, Telnet) over AX.25 UI frames. Optional **ChaCha20 stream cipher encryption** adds a second encryption layer.

## Features

- **KISS ↔ TCP bridging** — transparent frame forwarding
- **FTE always enabled** — payload bits encoded into observed protocol vocabularies (from `samples/*.json`)
- **Multiple cover protocols** — BBS/APRS (`bbs`), HTTP (`http`), Telnet (`telnet`), or rotating (`rotate`)
- **Optional ChaCha20 encryption** — `--encrypt --key "passphrase"` (nonce auto-derived from key)
- **Automatic chunking/reassembly** — 110-byte plaintext chunks, 255-chunk max per frame
- **AX.25 UI framing + KISS escape/unescape** — correct FEND/FESC handling

## Quick Start (Python)

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt

# Plain FTE (BBS cover, no extra encryption)
python3 kiss-bbs-fte.py

# With ChaCha20 encryption (passphrase key, deterministic nonce)
python3 kiss-bbs-fte.py --encrypt --key "my-secret-passphrase"

# Different cover protocol
python3 kiss-bbs-fte.py --cover http --max-cover-msg 200
```

Configure via environment variables or CLI flags:
```
APP_HOST=127.0.0.1  APP_PORT=8001
TNC_HOST=127.0.0.1  TNC_PORT=8002
SRC_CALL=NODE1-1    DST_CALL=BBS-1
COVER_PROTO=bbs     MAX_COVER_MSG=200
BBS_NARRATOR=bbs7plus  (or aprs)
CHACHA20_KEY=passphrase  (for --encrypt)
```

## Run via Container

```bash
# Pre-built image
podman pull ghcr.io/dougsko/kiss-fte-proxy:latest

# Host networking (typical: Direwolf on host)
podman run --rm --network host \
  -e APP_HOST=127.0.0.1 -e APP_PORT=8001 \
  -e TNC_HOST=127.0.0.1 -e TNC_PORT=8002 \
  -e SRC_CALL=NODEA-1 -e DST_CALL=NODEB-1 \
  -e CHACHA20_KEY="my-passphrase" \
  ghcr.io/dougsko/kiss-fte-proxy:latest \
  --encrypt
```

## Run via Quadlet (systemd)

```bash
mkdir -p ~/.config/containers/systemd/
cp quadlet/kiss-fte-proxy.container ~/.config/containers/systemd/
mkdir -p /etc/kiss-fte-proxy/
cp quadlet/kiss-fte-proxy.env.example /etc/kiss-fte-proxy/kiss-fte-proxy.env
# Edit env file as needed
systemctl --user daemon-reload
systemctl --user enable --now kiss-fte-proxy.service
```

## Encryption Notes

- `--encrypt` enables ChaCha20 stream cipher (bare, no AEAD) around the FTE payload
- `--key` accepts a **passphrase** (any string, SHA-256 → 32-byte key) or **64-char hex key**
- Nonce is **derived deterministically** from the key: `SHA256(key + b"kiss-fte-nonce")[:16]`
- Both peers sharing the same passphrase compute identical key+nonce — no nonce config needed

## Requirements

- Python 3.8+
- `pip install -r requirements.txt` (cryptography)