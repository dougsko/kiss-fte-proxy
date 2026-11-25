"""
Modular BBS narrator registry with pluggable narrator implementations.

Each narrator encodes raw payload bytes into a plausible cover-traffic format
and decodes it back. The proxy uses the registry to select a narrator by name
(e.g., via env var BBS_NARRATOR).

Plausible-deniability principles
--------------------------------
Real packet-radio traffic is inherently noisy and unpredictable: sequence
numbers skip, message types appear at random, ACKs arrive without matching
sends, and digipeat paths vary.  By mirroring that natural variation the
narrators ensure an observer cannot reliably distinguish cover traffic from
ordinary packet-radio chatter.  The non-determinism below is deliberate and
must NOT be "cleaned up" into a predictable pattern.
"""

from abc import ABC, abstractmethod
import base64
import re
import random
import textwrap


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
# Realistic APRS info-field cover formats. Each carries a base64-encoded
# payload so the traffic looks like genuine APRS while remaining fully
# decodable back to the original framed bytes.
#
#   Message   :ADDRESS:payload{SEQ}   addressed APRS message (control)
#   Status    >payload                APRS status report
#   Bulletin  :BLNn:payload           APRS bulletin
#
# The narrator rotates through these formats so cover traffic looks varied
# and plausible rather than repeating a single template. The part/total
# bookkeeping lives in the proxy's outer framing (struct.pack('!HBB', ...)),
# so the narrator only needs to round-trip the framed bytes.

APRS_MSG_RE = re.compile(r"^:(.+):([A-Za-z0-9+/=]+)\{(\d{1,3})\}$")
APRS_STATUS_RE = re.compile(r"^>([A-Za-z0-9+/=]+)$")
APRS_BULLETIN_RE = re.compile(r"^:BLN\d:([A-Za-z0-9+/=]+)$")

# Weighted variant distribution for data packets — message is most common
# (typical APRS), status/bulletin are less frequent but still plausible.
# Deniability: the weights mean the *type* sequence is unpredictable, so an
# observer cannot fingerprint the channel by packet-type patterns.
_APRS_VARIANT_WEIGHTS = {"message": 0.6, "status": 0.25, "bulletin": 0.15}


@register_narrator
class APRSNarrator(BBSBaseNarrator):
    """
    APRS narrator emitting several plausible APRS packet types.

    Control (small) packets are sent as addressed APRS messages, which
    resemble message retries/acks. Data packets are emitted in a
    weighted-random mix of message, status and bulletin formats so the
    cover traffic looks varied and plausible.

    Plausible-deniability features
    ------------------------------
    * Weighted-random variant selection (message > status > bulletin).
    * Sequence-number jitter: msg numbers advance by a random 1-3 steps,
      mimicking packets that are silently dropped/retried on a noisy RF
      channel instead of a clean +1 counter an observer could track.
    * Random bulletin IDs (BLN0..BLN9) so even the addressing varies.
    """

    name = "aprs"

    def __init__(self, src_call: str, dst_call: str):
        super().__init__(src_call, dst_call)
        self.msg_seq = random.randint(1, 999)

    def _next_seq(self) -> int:
        """Advance the sequence counter by a random jittered amount."""
        self.msg_seq = ((self.msg_seq - 1 + random.randint(1, 3)) % 999) + 1
        return self.msg_seq

    def _pick_variant(self) -> str:
        """Weighted-randomly select an APRS variant for this packet."""
        roll = random.random()
        cum = 0.0
        for variant, weight in _APRS_VARIANT_WEIGHTS.items():
            cum += weight
            if roll < cum:
                return variant
        return "message"

    def format_packet(self, payload: bytes, is_small_ctrl: bool, part: int = 1, total: int = 1) -> str:
        b64 = base64.b64encode(payload).decode("ascii")
        seq = self._next_seq()

        if is_small_ctrl:
            # Control packets look like addressed APRS messages (retries/acks)
            return f":{self.dst_call}:{b64}{{{seq:03d}}}"

        # Data packets use a weighted-random plausible APRS type
        variant = self._pick_variant()
        if variant == "message":
            return f":{self.dst_call}:{b64}{{{seq:03d}}}"
        if variant == "status":
            return f">{b64}"
        return f":BLN{random.randint(0, 9)}:{b64}"

    def decode_packet(self, bbs_text: str) -> bytes | None:
        text = bbs_text.strip()

        # Addressed message: :ADDR:b64{SEQ}
        m = APRS_MSG_RE.match(text)
        if m:
            try:
                return base64.b64decode(m.group(2), validate=True)
            except Exception:
                return None

        # Status report: >b64
        m = APRS_STATUS_RE.match(text)
        if m:
            try:
                return base64.b64decode(m.group(1), validate=True)
            except Exception:
                return None

        # Bulletin: :BLNn:b64
        m = APRS_BULLETIN_RE.match(text)
        if m:
            try:
                return base64.b64decode(m.group(1), validate=True)
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