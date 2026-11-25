import base64
import re
import socket
import struct
import threading
import textwrap
import time
import random

# --- Configuration ---
APP_LISTEN_ADDR = ("127.0.0.1", 8001)   # Upstream app (TCP KISS)
TNC_TARGET_ADDR = ("127.0.0.1", 8002)   # Direwolf / TNC KISS port
SRC_CALL = "NODE1-1"
DST_CALL = "BBS-1"

# Thresholds & Chunking
SMALL_CTRL_THRESHOLD = 32   # Frames <= 32B look like short BBS ACK/control lines
MAX_PLAINTEXT_CHUNK = 110   # Larger frames split into ~260B AX.25 7PLUS blocks

# KISS Constants
FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD


# --- BBS Encoding ---
def encode_bbs_packet(payload: bytes, is_small_ctrl: bool) -> str:
    b64 = base64.b64encode(payload).decode("ascii")
    if is_small_ctrl:
        return f"ACK [{b64}]\r"
    lines = ["M" + line for line in textwrap.wrap(b64, width=62)]
    body = "\r".join(lines)
    return (
        f" go_7+. 01 of 01 DATA 00000 0000\r"
        f"{body}\r"
        f" stop_7+. (0000/0000)\r"
        f"de {DST_CALL}>\r"
    )


CTRL_PARSE_RE = re.compile(r"^ACK \[([A-Za-z0-9+/=]+)\]\r$")

DATA_PARSE_RE = re.compile(
    r"^ go_7\+\. \d{2} of \d{2} [A-Z0-9_.]+ \d{5} [0-9A-F]{4}\r"
    r"([\s\S]+?)\r"
    r" stop_7\+\. \([0-9A-F]{4}/[0-9A-F]{4}\)\r"
    r"de [^>]+>\r$"
)


def decode_bbs_packet(bbs_text: str) -> bytes | None:
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


# --- KISS & AX.25 Framing ---
def kiss_escape(data: bytes) -> bytes:
    out = bytearray()
    for b in data:
        if b == FEND:
            out.extend([FESC, TFEND])
        elif b == FESC:
            out.extend([FESC, TFESC])
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


def unwrap_ax25_ui(ax25_frame: bytes) -> bytes | None:
    idx = 0
    while idx + 7 <= len(ax25_frame):
        last_bit = ax25_frame[idx + 6] & 0x01
        idx += 7
        if last_bit:
            break
    else:
        return None
    if len(ax25_frame) < idx + 3 or ax25_frame[idx : idx + 2] != b"\x03\xF0":
        return None
    return ax25_frame[idx + 2 :]


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
            del buf[: end + 1]
            if len(raw_frame) > 1 and (raw_frame[0] & 0x0F) == 0x00:
                yield kiss_unescape(raw_frame[1:])


# --- Reassembly & Proxy Session ---
class ReassemblyBuffer:
    def __init__(self, timeout: float = 30.0):
        self.pending: dict[int, tuple[float, int, dict[int, bytes]]] = {}
        self.timeout = timeout

    def add_chunk(self, msg_id: int, idx: int, total: int, data: bytes) -> bytes | None:
        now = time.monotonic()
        for k in [k for k, (ts, _, _) in self.pending.items() if now - ts > self.timeout]:
            del self.pending[k]

        if msg_id not in self.pending:
            self.pending[msg_id] = (now, total, {})
        _, exp_total, chunks = self.pending[msg_id]
        chunks[idx] = data

        if len(chunks) == exp_total:
            del self.pending[msg_id]
            return b"".join(chunks[i] for i in range(exp_total))
        return None


def handle_session(app_sock: socket.socket):
    tnc_sock = socket.create_connection(TNC_TARGET_ADDR)
    reassembler = ReassemblyBuffer()
    tx_msg_id = random.randint(0, 65535)

    def app_to_tnc():
        nonlocal tx_msg_id
        for frame in read_kiss_frames(app_sock):
            tx_msg_id = (tx_msg_id + 1) & 0xFFFF
            is_small_ctrl = len(frame) <= SMALL_CTRL_THRESHOLD

            chunks = [
                frame[i : i + MAX_PLAINTEXT_CHUNK]
                for i in range(0, max(1, len(frame)), MAX_PLAINTEXT_CHUNK)
            ]
            total = len(chunks)

            for idx, chunk in enumerate(chunks):
                framed_plain = struct.pack("!HBB", tx_msg_id, idx, total) + chunk
                bbs_text = encode_bbs_packet(framed_plain, is_small_ctrl).encode("ascii")
                ax25_out = wrap_ax25_ui(bbs_text)
                kiss_out = bytes([FEND, 0x00]) + kiss_escape(ax25_out) + bytes([FEND])

                tnc_sock.sendall(kiss_out)

    def tnc_to_app():
        for ax25_frame in read_kiss_frames(tnc_sock):
            info = unwrap_ax25_ui(ax25_frame)
            if not info:
                continue

            framed_plain = decode_bbs_packet(info.decode("ascii", errors="ignore"))
            if not framed_plain or len(framed_plain) < 4:
                continue

            msg_id, idx, total = struct.unpack("!HBB", framed_plain[:4])
            full_frame = reassembler.add_chunk(msg_id, idx, total, framed_plain[4:])
            if full_frame is not None:
                kiss_out = bytes([FEND, 0x00]) + kiss_escape(full_frame) + bytes([FEND])
                app_sock.sendall(kiss_out)

    threading.Thread(target=app_to_tnc, daemon=True).start()
    threading.Thread(target=tnc_to_app, daemon=True).start()


# --- Main Entry Point ---
if __name__ == "__main__":
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(APP_LISTEN_ADDR)
    server.listen(5)
    print(f"[*] kiss-bbs-fte listening on {APP_LISTEN_ADDR} -> {TNC_TARGET_ADDR}")
    print(f"[*] Using callsign {SRC_CALL} -> {DST_CALL}")
    try:
        while True:
            conn, addr = server.accept()
            print(f"[*] Session from {addr}")
            handle_session(conn)
    except KeyboardInterrupt:
        print("\n[*] Shutting down")
    finally:
        server.close()
