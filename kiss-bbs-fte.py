#!/usr/bin/env python3
import base64
import os
import re
import socket
import struct
import threading
import textwrap
import time
import random
import argparse
import hashlib
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms

from bbs_narrators import (
    FEND, FESC, TFEND, TFESC,
    create_narrator_from_env,
)

# --- Configuration (environment-overridable for two-node tests) ---
APP_LISTEN_ADDR = (os.getenv("APP_HOST", "127.0.0.1"), int(os.getenv("APP_PORT", "8001")))
TNC_TARGET_ADDR = (os.getenv("TNC_HOST", "127.0.0.1"), int(os.getenv("TNC_PORT", "8002")))
SRC_CALL = os.getenv("SRC_CALL", "NODE1-1")
DST_CALL = os.getenv("DST_CALL", "BBS-1")

SMALL_CTRL_THRESHOLD = int(os.getenv("SMALL_CTRL_THRESHOLD", "32"))
# Default chunk size for BBS mode; will be overridden for cover modes
MAX_PLAINTEXT_CHUNK = int(os.getenv("MAX_PLAINTEXT_CHUNK", "110"))

# Cover protocol configuration (defaults to bbs)
COVER_PROTO = os.getenv("COVER_PROTO", "bbs").lower()
MAX_COVER_MSG = int(os.getenv("MAX_COVER_MSG", "200"))
# FTE mode (observation-based encoding from pcap vocab) - always enabled
FTE_MODE = True

# Import cover codecs
from cover_codecs import get_codec, split_payload

# ---------------------------------------------------------------------------
# ChaCha20 stream cipher helper (bare stream, no AEAD)
# ---------------------------------------------------------------------------

def chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """XOR *data* with the ChaCha20 keystream (symmetric: encrypt == decrypt)."""
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# ---------------------------------------------------------------------------
# ChaCha20 stream cipher helper (bare stream, no AEAD)
# ---------------------------------------------------------------------------

def chacha20(key: bytes, nonce: bytes, data: bytes) -> bytes:
    """XOR *data* with the ChaCha20 keystream (symmetric: encrypt == decrypt)."""
    cipher = Cipher(algorithms.ChaCha20(key, nonce), mode=None)
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()

# ---------------------------------------------------------------------------
# Passphrase -> key derivation (SHA-256)
# ---------------------------------------------------------------------------

def derive_key_from_passphrase(passphrase: str) -> bytes:
    """Derive a 32-byte ChaCha20 key from a UTF-8 passphrase using SHA-256."""
    return hashlib.sha256(passphrase.encode("utf-8")).digest()


def derive_nonce_from_key(key: bytes) -> bytes:
    """Derive a deterministic 16-byte ChaCha20 nonce from the key.

    Both peers share the same key, so both independently compute the same
    nonce -- no nonce configuration or in-band transmission required.
    """
    return hashlib.sha256(key + b"kiss-fte-nonce").digest()[:16]

# ---------------------------------------------------------------------------
# KISS escape/unescape helpers
# ---------------------------------------------------------------------------

def kiss_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == FEND:
            out.extend((FESC, TFEND))
        elif b == FESC:
            out.extend((FESC, TFESC))
        else:
            out.append(b)
    return bytes(out)

def kiss_unescape(data: bytes) -> bytes:
    out = bytearray()
    i = 0
    while i < len(data):
        if data[i] == FESC and i + 1 < len(data):
            if data[i + 1] == TFEND:
                out.append(FEND)
            elif data[i + 1] == TFESC:
                out.append(FESC)
            else:
                out.extend((data[i], data[i + 1]))
            i += 2
        else:
            out.append(data[i])
            i += 1
    return bytes(out)


def encode_ax25_addr(callsign: str, last: bool = False) -> bytes:
    call, ssid = (callsign.split("-") + ["0"])[:2]
    call = call.ljust(6)[:6].upper()
    addr = bytearray((ord(c) << 1) for c in call)
    addr.append(0x60 | ((int(ssid) & 0x0F) << 1) | (0x01 if last else 0x00))
    return bytes(addr)


def wrap_ax25_ui(payload: bytes) -> bytes:
    hdr = bytearray()
    hdr.extend(encode_ax25_addr(DST_CALL, last=False))
    hdr.extend(encode_ax25_addr(SRC_CALL, last=True))
    hdr.extend(b"\x03\xF0")
    return bytes(hdr) + payload


def unwrap_ax25_ui(ax25_frame: bytes):
    idx = 0
    while idx + 7 <= len(ax25_frame):
        last_bit = ax25_frame[idx + 6] & 0x01
        idx += 7
        if last_bit:
            break
    else:
        return None
    if len(ax25_frame) < idx + 3 or ax25_frame[idx:idx + 2] != b"\x03\xF0":
        return None
    return ax25_frame[idx + 2:]


def read_kiss_frames(sock: socket.socket):
    buf = bytearray()
    while True:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                break
        except OSError:
            break
        buf.extend(chunk)
        while FEND in buf:
            start = buf.index(FEND)
            if start > 0:
                del buf[:start]
            if len(buf) < 2:
                break
            try:
                end = buf.index(FEND, 1)
            except ValueError:
                break
            raw_frame = bytes(buf[1:end])
            del buf[:end + 1]
            if len(raw_frame) > 1 and (raw_frame[0] & 0x0F) == 0x00:
                yield kiss_unescape(raw_frame[1:])


class ReassemblyBuffer:
    def __init__(self, timeout: float = 30.0, max_pending: int = 128):
        self.pending = {}
        self.timeout = timeout
        self.max_pending = max_pending

    def add_chunk(self, msg_id: int, idx: int, total: int, data: bytes):
        now = time.monotonic()
        for key in [k for k, (ts, _, _) in self.pending.items() if now - ts > self.timeout]:
            del self.pending[key]
        if total < 1 or idx >= total:
            return None
        if msg_id not in self.pending:
            if len(self.pending) >= self.max_pending:
                oldest = min(self.pending, key=lambda k: self.pending[k][0])
                del self.pending[oldest]
            self.pending[msg_id] = (now, total, {})
        created, expected_total, chunks = self.pending[msg_id]
        if expected_total != total:
            del self.pending[msg_id]
            return None
        created, expected_total, chunks = self.pending[msg_id]
        if idx in chunks:
            if chunks[idx] != data:
                del self.pending[msg_id]
            return None
        chunks[idx] = data
        self.pending[msg_id] = (created, expected_total, chunks)
        if len(chunks) == expected_total:
            try:
                result = b"".join(chunks[i] for i in range(expected_total))
            except KeyError:
                return None
            del self.pending[msg_id]
            return result
        return None


def handle_session(app_sock: socket.socket, enc_key: bytes = None,
                   enc_nonce: bytes = None, encrypt: bool = False):
    tnc_sock = socket.create_connection(TNC_TARGET_ADDR, timeout=10)
    tnc_sock.settimeout(None)
    reassembler = ReassemblyBuffer()
    fte_reasm = {}
    tx_msg_id = random.randint(0, 65535)

    # Determine cover mode and codec for this session (bbs is now a cover codec too)
    cover_codec = get_codec(COVER_PROTO, max_cover_msg=MAX_COVER_MSG, fte_mode=FTE_MODE)
    # header_overhead is 0 for all codecs: sequencing lives in the cover envelope,
    # so the chunk size is simply the codec's per-message capacity.
    chunk_size = max(1, cover_codec.max_payload_bytes())

    def app_to_tnc():
        try:
            for frame in read_kiss_frames(app_sock):
                if encrypt:
                    frame = chacha20(enc_key, enc_nonce, frame)
                cs = chunk_size
                chunks = [frame[i:i + max(1, cs)] for i in range(0, max(1, len(frame)), cs)]
                total = len(chunks)
                if total > 255:
                    raise ValueError("frame exceeds 255-chunk protocol limit")
                for idx, chunk in enumerate(chunks):
                    # All paths (FTE + base64, http/telnet/bbs/rotate) use the same
                    # envelope: raw chunk + sequencing carried in the cover message.
                    cover_text = cover_codec.encode(chunk, idx, total, len(frame))
                    ax25_out = wrap_ax25_ui(cover_text.encode('latin-1'))
                    kiss_out = bytes((FEND, 0x00)) + kiss_escape(ax25_out) + bytes((FEND,))
                    tnc_sock.sendall(kiss_out)
        except (OSError, ValueError) as exc:
            print(f"[proxy] app->tnc stopped: {exc}", flush=True)
        finally:
            try:
                tnc_sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    def tnc_to_app():
        reasm = {}
        try:
            for ax25_frame in read_kiss_frames(tnc_sock):
                info = unwrap_ax25_ui(ax25_frame)
                if info is None:
                    continue
                decoded, idx, total, total_len = cover_codec.decode_meta(
                    info.decode('latin-1', errors='ignore'))
                if total < 1 or idx < 0 or idx >= total:
                    continue
                # Truncate per-frame decoded payload to the known chunk_size.
                # This removes FTE padding from inner codecs in rotate mode.
                if len(decoded) > chunk_size:
                    decoded = decoded[:chunk_size]
                reasm[idx] = decoded
                if len(reasm) == total and all(i in reasm for i in range(total)):
                    full_frame = b"".join(reasm[i] for i in range(total))
                    if total_len is not None and len(full_frame) >= total_len:
                        full_frame = full_frame[:total_len]
                    if encrypt:
                        full_frame = chacha20(enc_key, enc_nonce, full_frame)
                    reasm.clear()
                    kiss_out = bytes((FEND, 0x00)) + kiss_escape(full_frame) + bytes((FEND,))
                    app_sock.sendall(kiss_out)
        except OSError as exc:
            print(f"[proxy] tnc->app stopped: {exc}", flush=True)
        finally:
            try:
                app_sock.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threading.Thread(target=app_to_tnc, daemon=True).start()
    threading.Thread(target=tnc_to_app, daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="KISS FTE Proxy with optional cover protocol support")
    parser.add_argument("--cover", choices=["bbs", "http", "telnet", "rotate"], default=COVER_PROTO,
                        help="Cover protocol to use (bbs, http, telnet, or rotate)")
    parser.add_argument("--max-cover-msg", type=int, default=MAX_COVER_MSG,
                        help="Maximum size of cover messages in bytes")
    parser.add_argument("--src-call", default=None,
                        help="Fixed source callsign (overrides env/default)")
    parser.add_argument("--dst-call", default=None,
                        help="Fixed destination callsign (overrides env/default)")
    parser.add_argument("--encrypt", action="store_true", default=False,
                        help="Enable ChaCha20 stream cipher encryption (key: --key or CHACHA20_KEY env)")
    parser.add_argument("--key", default=None,
                        help="Hex-encoded 32-byte ChaCha20 key (64 hex chars) OR a passphrase string (will be SHA-256 hashed to 32 bytes). Can also be set via CHACHA20_KEY env.")
    args = parser.parse_args()

    COVER_PROTO = args.cover
    MAX_COVER_MSG = args.max_cover_msg
    FTE_MODE = True  # FTE is always enabled
    if args.src_call:
        SRC_CALL = args.src_call
    if args.dst_call:
        DST_CALL = args.dst_call

    # Encryption setup
    enc_key = None
    encrypt_enabled = args.encrypt
    if encrypt_enabled:
        passphrase = args.key or os.getenv("CHACHA20_KEY")
        if not passphrase:
            parser.error("Encryption enabled but no key provided (use --key or CHACHA20_KEY env)")
        # Accept either a raw passphrase (any string) or a 32-byte hex key.
        try:
            enc_key = bytes.fromhex(passphrase)
            if len(enc_key) != 32:
                parser.error("Key must be 32 bytes (64 hex chars)")
        except ValueError:
            # Not valid hex -> treat as a passphrase and derive a key via SHA-256
            enc_key = derive_key_from_passphrase(passphrase)
        # Derive nonce deterministically from the key so both peers agree
        enc_nonce = derive_nonce_from_key(enc_key)
        print(f"[*] Encryption: ENABLED (ChaCha20 stream cipher, derived nonce from key)", flush=True)
    else:
        enc_nonce = None

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(APP_LISTEN_ADDR)
    server.listen(5)
    print(f"[*] kiss-fte-proxy listening on {APP_LISTEN_ADDR} -> {TNC_TARGET_ADDR}", flush=True)
    print(f"[*] Using callsign {SRC_CALL} -> {DST_CALL}", flush=True)
    print(f"[*] Cover protocol: {COVER_PROTO}, max message size: {MAX_COVER_MSG} bytes", flush=True)
    if FTE_MODE:
        print(f"[*] FTE mode: ENABLED (observation-based encoding from pcap vocab)", flush=True)
    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] Session from {addr}", flush=True)
            threading.Thread(
                target=handle_session,
                args=(conn, enc_key, enc_nonce, encrypt_enabled),
                daemon=True,
            ).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down", flush=True)
    finally:
        server.close()