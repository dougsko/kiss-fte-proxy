import base64
import os
import re
import socket
import struct
import threading
import textwrap
import time
import random

# --- Configuration (environment-overridable for two-node tests) ---
APP_LISTEN_ADDR = (os.getenv("APP_HOST", "127.0.0.1"), int(os.getenv("APP_PORT", "8001")))
TNC_TARGET_ADDR = (os.getenv("TNC_HOST", "127.0.0.1"), int(os.getenv("TNC_PORT", "8002")))
SRC_CALL = os.getenv("SRC_CALL", "NODE1-1")
DST_CALL = os.getenv("DST_CALL", "BBS-1")

SMALL_CTRL_THRESHOLD = int(os.getenv("SMALL_CTRL_THRESHOLD", "32"))
MAX_PLAINTEXT_CHUNK = int(os.getenv("MAX_PLAINTEXT_CHUNK", "110"))
FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD

# --- Realistic BBS Narrative Generator ---
FILE_TEMPLATES = [
    ("SYSUPD", "ZIP"),
    ("WXMAPS", "GIF"),
    ("NODELST", "LZH"),
    ("BPQCFG", "TGZ"),
    ("PROPAG", "DAT"),
]

CORRUPTION_NOTICES = [
    "*** Frame CRC mismatch - requesting block retry",
    "*** Line noise detected (BAD FCS) - NAK sent",
    "*** Checksum error on block - re-syncing stream",
]


class BBSNarrator:
    """Maintains a believable sequential 7PLUS file upload narrative across packets."""

    def __init__(self, src_call: str, dst_call: str):
        self.src_call = src_call
        self.dst_call = dst_call
        self.file_seq = random.randint(1, 20)
        self.part_num = 1
        self.part_tot = random.randint(8, 16)
        self.file_crc = f"{random.randint(0, 0xFFFF):04X}"
        self.filename = self._next_filename()
        self.last_part_num = 1

    def _next_filename(self) -> str:
        prefix, ext = random.choice(FILE_TEMPLATES)
        fname = f"{prefix}{self.file_seq:02d}.{ext}"
        self.file_seq = (self.file_seq % 99) + 1
        return fname

    def format_packet(self, payload: bytes, is_small_ctrl: bool, part: int = 1, total: int = 1) -> str:
        b64 = base64.b64encode(payload).decode("ascii")

        if is_small_ctrl:
            return (
                f"ACK {self.last_part_num:02d} [{b64}] OK - Send next block\r"
                f"de {self.src_call}>\r"
            )

        lines = ["M" + line for line in textwrap.wrap(b64, width=62)]
        body = "\r".join(lines)
        block_crc = f"{random.randint(0, 0xFFFF):04X}"
        curr_part = part if total > 1 else self.part_num
        status_line = ""

        if total == 1:
            curr_part = self.part_num
            self.last_part_num = curr_part
            self.part_num = 1
            self.part_tot = random.randint(8, 16)
            self.file_crc = f"{random.randint(0, 0xFFFF):04X}"
            self.filename = self._next_filename()
        elif curr_part == self.part_tot:
            status_line = f"7PLUS extraction complete - {self.filename} saved\r"
            self.part_num = 1
            self.part_tot = random.randint(8, 16)
            self.file_crc = f"{random.randint(0, 0xFFFF):04X}"
            self.filename = self._next_filename()
        else:
            simulate_retry = (curr_part < self.part_tot) and (random.random() < 0.15)
            if simulate_retry:
                status_line = f"{random.choice(CORRUPTION_NOTICES)}\r"
            else:
                status_line = ""
                self.part_num += 1

        return (
            f" go_7+. {curr_part:02d} of {total if total > 1 else self.part_tot:02d} "
            f"{self.filename} 00512 {self.file_crc}\r"
            f"{body}\r"
            f"{status_line}"
            f" stop_7+. ({self.file_crc}/{block_crc})\r"
            f"de {self.dst_call}>\r"
        )


CTRL_PARSE_RE = re.compile(r"^ACK \d{2} \[([A-Za-z0-9+/=]+)\] OK - Send next block\rde [^>]+>\r$")

DATA_PARSE_RE = re.compile(
    r"^ go_7\+\. \d{2} of \d{2} [A-Z0-9_.]+ \d{5} [0-9A-F]{4}\r"
    r"([\s\S]+?)\r"
    r"(?:(?:\*\*\* [^\r]+|7PLUS extraction complete - [^\r]+)\r)?"
    r" stop_7\+\. \([0-9A-F]{4}/[0-9A-F]{4}\)\r"
    r"de [^>]+>\r$"
)


def decode_bbs_packet(bbs_text: str):
    m_ctrl = CTRL_PARSE_RE.match(bbs_text)
    if m_ctrl:
        try:
            return base64.b64decode(m_ctrl.group(1), validate=True)
        except Exception:
            return None
    m_data = DATA_PARSE_RE.match(bbs_text)
    if not m_data:
        return None
    lines = m_data.group(1).split("\r")
    if not all(line.startswith("M") for line in lines if line):
        return None
    b64_str = "".join(line[1:] for line in lines if line)
    try:
        return base64.b64decode(b64_str, validate=True)
    except Exception:
        return None


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
    bbs_narrator = BBSNarrator(SRC_CALL, DST_CALL)

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
                    bbs_text = bbs_narrator.format_packet(
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
                framed = decode_bbs_packet(info.decode("ascii", errors="ignore"))
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
