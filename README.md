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

## Container / Quadlet

Pre-built images are published to **ghcr.io/dougsko/kiss-fte-proxy** with tags `latest`, `sha-<short>`, and semver tags from Git releases.

### Using the image directly

```bash
# Pull and run with defaults (host networking, env file optional)
podman pull ghcr.io/dougsko/kiss-fte-proxy:latest

# Run with host networking (proxy binds 127.0.0.1:8001, reaches Direwolf on 127.0.0.1:8002)
podman run --rm --network host \
  -e APP_HOST=127.0.0.1 -e APP_PORT=8001 \
  -e TNC_HOST=127.0.0.1 -e TNC_PORT=8002 \
  -e SRC_CALL=NODEA-1 -e DST_CALL=NODEB-1 \
  -e BBS_NARRATOR=bbs7plus \
  ghcr.io/dougsko/kiss-fte-proxy:latest
```

### Using the Quadlet (systemd service)

The `quadlet/` directory contains a ready-to-use systemd-generated container unit:

```bash
# 1. Install the quadlet unit (user or system mode)
mkdir -p ~/.config/containers/systemd/
cp quadlet/kiss-fte-proxy.container ~/.config/containers/systemd/

# 2. Create the environment file
mkdir -p /etc/kiss-fte-proxy/
cp quadlet/kiss-fte-proxy.env.example /etc/kiss-fte-proxy/kiss-fte-proxy.env
# Edit /etc/kiss-fte-proxy/kiss-fte-proxy.env as needed

# 3. Reload systemd and start
systemctl --user daemon-reload
systemctl --user enable --now kiss-fte-proxy.service
```

The quadlet uses **host networking** so the proxy binds directly on the host's `APP_PORT` (default `8001`) and connects to `TNC_HOST:TNC_PORT` (default `127.0.0.1:8002`) — matching a typical host-running Direwolf. To expose the proxy on all interfaces, set `APP_HOST=0.0.0.0` in the env file.

#### Alternative: Bridge network (Direwolf in another container)

If Direwolf runs in a separate container, create a Podman network quadlet and reference it:

```ini
# quadlet/kiss-fte-proxy.network
[Network]
Driver=bridge

# quadlet/kiss-fte-proxy.container (bridge variant)
[Container]
Image=ghcr.io/dougsko/kiss-fte-proxy:latest
AutoUpdate=registry
EnvironmentFile=/etc/kiss-fte-proxy/kiss-fte-proxy.env
Network=kiss-fte-proxy.network
PublishPort=8001:8001
```

Set `TNC_HOST=direwolf` (the container name) in the env file.

### Auto-updates

The quadlet includes `AutoUpdate=registry` and the corresponding label. With `podman-auto-update` enabled, systemd will automatically pull new images and restart the service:

```bash
# Enable daily auto-update check
systemctl --user enable --now podman-auto-update.timer
```

## Requirements
- Python 3.8+
- Standard library only (no `cryptography` dependency)
