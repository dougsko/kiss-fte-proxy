import base64
import os
import re
import socket
import struct
import threading
import time
import random
import textwrap
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# --- Configuration ---
APP_LISTEN_ADDR = ("127.0.0.1", 8001)   # Upstream app (Reticulum / TCP KISS)
TNC_TARGET_ADDR = ("127.0.0.1", 8002)   # Direwolf / TNC KISS port
SRC_CALL = "NODE1-1"
DST_CALL = "BBS-1"

# Shared 32-byte AES-256-GCM key (must match on both ends)
AES_KEY = bytes.fromhex("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff")
aesgcm = AESGCM(AES_KEY)

# Thresholds & Chunking
SMALL_CTRL_THRESHOLD = 32   # Frames <= 32B look like short BBS ACK/control lines
MAX_PLAINTEXT_CHUNK = 110   # Larger frames split into ~260B AX.25 7PLUS blocks

# KISS Constants
FEND = 0xC0
FESC = 0xDB
TFEND = 0xDC
TFESC = 0xDD

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


class TransferNarrator:
    """Maintains a believable sequential 7PLUS file upload narrative across packets."""

    def __init__(self):
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

    def format_packet(self, ciphertext: bytes, is_small_ctrl: bool) -> str:
        b64_payload = base64.b64encode(ciphertext).decode("ascii")

        # 1. Small upstream packets (ACKs, keepalives) -> Short BBS control response
        if is_small_ctrl:
            return (
                f"ACK {self.last_part_num:02d} [{b64_payload}] OK - Send next block\r"
                f"de {SRC_CALL}>\r"
            )

        # 2. Data packets -> Sequential 7PLUS file block
        lines = ["M" + line for line in textwrap.wrap(b64_payload, width=62)]
        body = "\r".join(lines)
        block_crc = f"{random.randint(0, 0xFFFF):04X}"
        curr_part = self.part_num
        self.last_part_num = curr_part

        # Decide whether this packet simulates a transient retry (~20%) or clean advance (~80%)
        simulate_retry = (curr_part < self.part_tot) and (random.random() < 0.20)

        if simulate_retry:
            notice = random.choice(CORRUPTION_NOTICES)
            status_line = f"{notice}\r"
            # Do NOT increment self.part_num so the next packet looks like a retry of curr_part
        elif curr_part == self.part_tot:
            status_line = f"7PLUS extraction complete - {self.filename} saved\r"
            # Roll over to a brand new file for the next packet
            self.part_num = 1
            self.part_tot = random.randint(8, 16)
            self.file_crc = f"{random.randint(0, 0xFFFF):04X}"
            self.filename = self._next_filename()
        else:
            status_line = ""
            self.part_num += 1

        return (
            f" go_7+. {curr_part:02d} of {self.part_tot:02d} {self.filename} 00512 {self.file_crc}\r"
            f"{body}\r"
            f"{status_line}"
            f" stop_7+. ({self.file_crc}/{block_crc})\r"
            f"de {DST_CALL}>\r"
        )


# --- Decoders for Both Asymmetric Formats ---
CTRL_PARSE_RE = re.compile(r"^ACK \d{2} \[([A-Za-z0-9+/=]+)\] OK - Send next block\rde [^>]+>\r$")

SEVENPLUS_PARSE_RE = re.compile(
    r"^ go_7\+\. \d{2} of \d{2} [A-Z0-9_.]+ \d{5} [0-9A-F]{4}\r"
    r"([\s\S]+?)\r"
    r"(?:(?:\*\*\* [^\r]+|7PLUS extraction complete - [^\r]+)\r)?"
    r" stop_7\+\. \([0-9A-F]{4}/[0-9A-F]{4}\)\r"
    r"de [^>]+>\r$"
)


def decode_bbs_packet(bbs_text: str) -> bytes | None:
    # Try short ACK/control format first
    m_ctrl = CTRL_PARSE_RE.match(bbs_text)
    if m_ctrl:
        try:
            return base64.b64decode(m_ctrl.group(1), validate=True)
        except Exception:
            return None

    # Otherwise try 7PLUS file block format
    m_data = SEVENPLUS_PARSE_RE.match(bbs_text)
    if not m_data:
        return None

    lines = m_data.group(1).split("\r")
    if not all(line.startswith("M") for line in lines):
        return None

    b64_str = "".join(line[1:] for line in lines)
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
            if len(raw_frame) > 1 and (raw_frame & 0x0F) == 0x00:
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
    narrator = TransferNarrator()
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
                nonce = os.urandom(12)
                ciphertext = nonce + aesgcm.encrypt(nonce, framed_plain, None)

                bbs_text = narrator.format_packet(ciphertext, is_small_ctrl).encode("ascii")
                ax25_out = wrap_ax25_ui(bbs_text)
                kiss_out = bytes([FEND, 0x00]) + kiss_escape(ax25_out) + bytes([FEND])

                time.sleep(random.uniform(0.08, 0.30))
                tnc_sock.sendall(kiss_out)

    def tnc_to_app():
        for ax25_frame in read_kiss_frames(tnc_sock):
            info = unwrap_ax25_ui(ax25_frame)
            if not info:
                continue

            ciphertext = decode_bbs_packet(info.decode("ascii", errors="ignore"))
            if not ciphertext or len(ciphertext) < 28:
                continue

            try:
                nonce, ct = ciphertext[:12], ciphertext[12:]
                framed_plain = aesgcm.decrypt(nonce, ct, None)
            except Exception:
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



