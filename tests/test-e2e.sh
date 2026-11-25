#!/usr/bin/env bash
set -Eeuo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"
NETWORK="kiss-fte-test"
IMAGE="localhost/kiss-fte-test:local"
DW_IMAGE="ghcr.io/dougsko/direwolf:latest"
ARTIFACTS="$ROOT/artifacts"
mkdir -p "$ARTIFACTS"

cleanup() {
  set +e
  for name in kiss-test-runner kiss-bridge proxy-a proxy-b direwolf-a direwolf-b; do
    podman rm -f "$name" >/dev/null 2>&1
  done
  podman network rm "$NETWORK" >/dev/null 2>&1
}
trap cleanup EXIT

command -v podman >/dev/null || { echo "podman is required" >&2; exit 1; }
podman network create "$NETWORK" >/dev/null 2>&1 || true
podman build -t "$IMAGE" -f Containerfile.proxy .
podman pull "$DW_IMAGE"

# Dire Wolf's KISSCOPY distributes frames from one KISS client to the others.
# The bridge is a KISS client on both TNCs and relays frames between them.
podman run -d --name direwolf-a --network "$NETWORK" \
  -v "$ROOT/direwolf/node-a.conf:/config/direwolf.conf:ro,Z" \
  "$DW_IMAGE" -c /config/direwolf.conf -t 0 >/dev/null
podman run -d --name direwolf-b --network "$NETWORK" \
  -v "$ROOT/direwolf/node-b.conf:/config/direwolf.conf:ro,Z" \
  "$DW_IMAGE" -c /config/direwolf.conf -t 0 >/dev/null

podman run -d --name proxy-a --network "$NETWORK" \
  -e APP_HOST=0.0.0.0 -e APP_PORT=8001 \
  -e TNC_HOST=direwolf-a -e TNC_PORT=8001 \
  -e SRC_CALL=NODEA-1 -e DST_CALL=NODEB-1 \
  "$IMAGE" >/dev/null
podman run -d --name proxy-b --network "$NETWORK" \
  -e APP_HOST=0.0.0.0 -e APP_PORT=8001 \
  -e TNC_HOST=direwolf-b -e TNC_PORT=8001 \
  -e SRC_CALL=NODEB-1 -e DST_CALL=NODEA-1 \
  "$IMAGE" >/dev/null

podman run -d --name kiss-bridge --network "$NETWORK" \
  -e DW_A_HOST=direwolf-a -e DW_B_HOST=direwolf-b \
  -e PCAP_PATH=/artifacts/transport.pcap \
  -v "$ARTIFACTS:/artifacts:Z" \
  --entrypoint python "$IMAGE" /app/kiss_bridge.py >/dev/null

# Wait for both proxy listeners and the bridge's KISS connections.
for i in $(seq 1 60); do
  if podman logs proxy-a 2>&1 | grep -q 'listening' && \
     podman logs proxy-b 2>&1 | grep -q 'listening' && \
     podman logs kiss-bridge 2>&1 | grep -q 'PCAP:'; then
    break
  fi
  sleep 1
done

podman run --rm --name kiss-test-runner --network "$NETWORK" \
  --entrypoint python "$IMAGE" /app/e2e.py | tee "$ARTIFACTS/results.txt"

echo
echo "PCAP: $ARTIFACTS/transport.pcap"
echo "Logs: podman logs proxy-a / proxy-b / direwolf-a / direwolf-b / kiss-bridge"
