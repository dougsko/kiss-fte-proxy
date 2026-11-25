import base64
import os
import re
import socket
import struct
import threading
import textwrap
import time
import random

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
MAX_PLAINTEXT_CHUNK = int(os.getenv("MAX_PLAINTEXT_CHUNK", "110"))


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
                # Preserve malformed escape bytes instead of silently dropping data.
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
        chunk = sock.recv(4096)
        if not chunk:
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
            # First byte is the KISS command; command 0 is data on port 0.
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


def handle_session(app_sock: socket.socket):
    tnc_sock = socket.create_connection(TNC_TARGET_ADDR, timeout=10)
    tnc_sock.settimeout(None)
    reassembler = ReassemblyBuffer()
    tx_msg_id = random.randint(0, 65535)
    narrator = create_narrator_from_env(SRC_CALL, DST_CALL)

    def app_to_tnc():
        nonlocal tx_msg_id
        try:
            for frame in read_kiss_frames(app_sock):
                tx_msg_id = (tx_msg_id + 1) & 0xFFFF
                is_small_ctrl = len(frame) <= SMALL_CTRL_THRESHOLD
                chunks = [frame[i:i + MAX_PLAINTEXT_CHUNK]
                          for i in range(0, max(1, len(frame)), MAX_PLAINTEXT_CHUNK)]
                total = len(chunks)
                if total > 255:
                    raise ValueError("frame exceeds 255-chunk protocol limit")
                for idx, chunk in enumerate(chunks):
                    framed = struct.pack("!HBB", tx_msg_id, idx, total) + chunk
                    bbs_text = narrator.format_packet(
                        framed, is_small_ctrl, idx + 1, total
                    ).encode("ascii")
                    ax25_out = wrap_ax25_ui(bbs_text)
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
        try:
            for ax25_frame in read_kiss_frames(tnc_sock):
                info = unwrap_ax25_ui(ax25_frame)
                if info is None:
                    continue
                framed = narrator.decode_packet(info.decode("ascii", errors="ignore"))
                if framed is None or len(framed) < 4:
                    continue
                msg_id, idx, total = struct.unpack("!HBB", framed[:4])
                full_frame = reassembler.add_chunk(msg_id, idx, total, framed[4:])
                if full_frame is not None:
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
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(APP_LISTEN_ADDR)
    server.listen(5)
    print(f"[*] kiss-bbs-fte listening on {APP_LISTEN_ADDR} -> {TNC_TARGET_ADDR}", flush=True)
    print(f"[*] Using callsign {SRC_CALL} -> {DST_CALL}", flush=True)
    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] Session from {addr}", flush=True)
            threading.Thread(target=handle_session, args=(conn,), daemon=True).start()
    except KeyboardInterrupt:
        print("\n[*] Shutting down", flush=True)
    finally:
        server.close()
