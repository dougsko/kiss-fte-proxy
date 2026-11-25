"""
Modular BBS narrator registry with pluggable narrator implementations.

Each narrator encodes raw payload bytes into a plausible cover-traffic format
and decodes it back. The proxy uses the registry to select a narrator by name
(e.g., via env var BBS_NARRATOR).
"""

from abc import ABC, abstractmethod
import base64
import re
import textwrap
import random
import time


# --- Constants shared with proxy ---
FEND, FESC, TFEND, TFESC = 0xC0, 0xDB, 0xDC, 0xDD


# --- Base narrator interface ---
class BBSBaseNarrator(ABC):
    """Abstract base for all BBS/cover-traffic narrators."""

    name: str = "base"

    def __init__(self, src_call: str, dst_call: str):
        self.src_call = src_call
        self.dst_call = dst_call

    @abstractmethod
    def format_packet(self, payload: bytes, is_small_ctrl: bool, part: int = 1, total: int = 1) -> str:
        """Encode payload into cover-traffic text format."""
        ...

    @abstractmethod
    def decode_packet(self, bbs_text: str) -> bytes | None:
        """Decode cover-traffic text back to raw payload bytes."""
        ...


# --- Registry ---
NARRATORS: dict[str, type[BBSBaseNarrator]] = {}


def register_narrator(cls: type[BBSBaseNarrator]) -> type[BBSBaseNarrator]:
    """Decorator to register a narrator class in the global registry."""
    NARRATORS[cls.name] = cls
    return cls


def get_narrator(name: str) -> type[BBSBaseNarrator]:
    """Get narrator class by name, or raise if unknown."""
    if name not in NARRATORS:
        raise ValueError(f"Unknown narrator: {name!r}. Available: {list(NARRATORS)}")
    return NARRATORS[name]


# --- BBS 7PLUS narrator (original format) ---
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


BBSB7PLUS_CTRL_RE = re.compile(
    r"^ACK \d{2} \[([A-Za-z0-9+/=]+)\] OK - Send next block\rde [^>]+>\r$"
)

BBSB7PLUS_DATA_RE = re.compile(
    r"^ go_7\+\. \d{2} of \d{2} [A-Z0-9_.]+ \d{5} [0-9A-F]{4}\r"
    r"([\s\S]+?)\r"
    r"(?:(?:\*\*\* [^\r]+|7PLUS extraction complete - [^\r]+)\r)?"
    r" stop_7\+\. \([0-9A-F]{4}/[0-9A-F]{4}\)\r"
    r"de [^>]+>\r$"
)


@register_narrator
class BBSB7PlusNarrator(BBSBaseNarrator):
    """Original 7PLUS-style BBS file upload narrative."""

    name = "bbs7plus"

    def __init__(self, src_call: str, dst_call: str):
        super().__init__(src_call, dst_call)
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

    def decode_packet(self, bbs_text: str) -> bytes | None:
        # Try control format first
        m_ctrl = BBSB7PLUS_CTRL_RE.match(bbs_text)
        if m_ctrl:
            try:
                return base64.b64decode(m_ctrl.group(1), validate=True)
            except Exception:
                return None

        # Try 7PLUS data format
        m_data = BBSB7PLUS_DATA_RE.match(bbs_text)
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


# --- APRS narrator ---
# APRS message format: >TOCALL,PATH:MSG
# We encode payload as base64 in a text message: >DST_CALL,APRS:<b64>
# For small control: >DST_CALL,APRS:ACK:<b64>
# For data: >DST_CALL,APRS:DATA:<b64>
# We use a sequence number to simulate conversation flow.

APRS_CTRL_RE = re.compile(r"^>(\w+)>(\w+):ACK:(\d+):([A-Za-z0-9+/=]+)$")
APRS_DATA_RE = re.compile(r"^>(\w+)>(\w+):DATA:(\d+):([A-Za-z0-9+/=]+)$")


@register_narrator
class APRSNarrator(BBSBaseNarrator):
    """
    APRS-style text message narrator.

    Encodes payload into APRS text messages:
    - Small ctrl:  >DST>SRC:ACK:seq:base64
    - Data:        >DST>SRC:DATA:seq:base64
    """

    name = "aprs"

    def __init__(self, src_call: str, dst_call: str):
        super().__init__(src_call, dst_call)
        self.msg_seq = random.randint(1, 1000)
        self.last_ack_seq = 0

    def format_packet(self, payload: bytes, is_small_ctrl: bool, part: int = 1, total: int = 1) -> str:
        b64 = base64.b64encode(payload).decode("ascii")
        self.msg_seq = (self.msg_seq % 9999) + 1
        seq = f"{self.msg_seq:04d}"

        if is_small_ctrl:
            # Small ctrl packets appear as ACK messages
            self.last_ack_seq = self.msg_seq
            return f">{self.dst_call}>{self.src_call}:ACK:{seq}:{b64}"
        else:
            # Data packets appear as DATA messages
            # If multi-part, include part/total in payload metadata
            if total > 1:
                # Encode part info into the message
                return f">{self.dst_call}>{self.src_call}:DATA:{seq}:P{part:02d}T{total:02d}:{b64}"
            return f">{self.dst_call}>{self.src_call}:DATA:{seq}:{b64}"

    def decode_packet(self, bbs_text: str) -> bytes | None:
        # Try ACK format
        m_ctrl = APRS_CTRL_RE.match(bbs_text.strip())
        if m_ctrl:
            try:
                return base64.b64decode(m_ctrl.group(4), validate=True)
            except Exception:
                return None

        # Try DATA format (with or without part info)
        m_data = APRS_DATA_RE.match(bbs_text.strip())
        if m_data:
            try:
                b64 = m_data.group(4)
                # Strip part prefix if present
                if b64.startswith("P") and "T" in b64:
                    # Format: P01T03:actual_b64
                    b64 = b64.split(":", 1)[1]
                return base64.b64decode(b64, validate=True)
            except Exception:
                return None
        return None


# --- Utility: auto-select narrator from env ---
def create_narrator_from_env(src_call: str, dst_call: str) -> BBSBaseNarrator:
    """Create narrator instance based on BBS_NARRATOR env var (default: bbs7plus)."""
    import os
    name = os.getenv("BBS_NARRATOR", "bbs7plus").lower()
    cls = get_narrator(name)
    return cls(src_call, dst_call)