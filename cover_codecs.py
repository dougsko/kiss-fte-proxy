#!/usr/bin/env python3
"""
Pluggable cover-protocol codecs for kiss-fte-proxy.

Every KISS-framed chunk's payload is encoded into a cover message (HTTP
request, Telnet IAC sequence, or BBS/APRS narrative).  Sequencing metadata
(part index, total parts, total length) is carried *inside the cover message
itself* -- X-Next for HTTP, a dedicated subnegotiation marker for Telnet, and
the "NN of TT" block header for BBS -- so the payload handed to ``encode`` is
always the raw chunk with **no internal framing header**.

This keeps all codecs symmetric and lets ``RotatingCoverCodec`` alternate
cover protocols per frame without any prefix byte: the receiver identifies the
protocol from the cover text itself (HTTP starts with "GET", Telnet contains
an IAC 0xFF byte, BBS matches a narrator signature).

Codec interface
---------------
class CoverCodec(ABC):
    name                  -- string used for logging
    header_overhead       -- bytes the codec consumes internally (always 0 now)
    max_payload_bytes()   -- max payload bytes per single cover message
    encode(data, part_idx, total_parts, total_len=None) -> str
    decode(cover_text) -> bytes                       # raw payload bytes
    decode_meta(cover_text) -> (payload, part_idx, total_parts, total_len)
"""

from abc import ABC, abstractmethod
import math, base64, re, os

# ---------------------------------------------------------------------------
# FTE vocabulary loader
# ---------------------------------------------------------------------------
_VOCAB = None
_VOCAB_PATH = None


def _load_fte_vocab(path=None):
    """Lazy-load the observation-based FTE vocabulary."""
    global _VOCAB, _VOCAB_PATH
    if _VOCAB is not None and _VOCAB_PATH == path:
        return _VOCAB
    if path is None:
        path = os.path.join(os.path.dirname(__file__), "samples", "vocab_all.json")
    try:
        from tools.fte_vocab import FteVocab
        _VOCAB = FteVocab(path)
        _VOCAB_PATH = path
    except Exception as exc:
        print(f"[cover_codecs] FTE vocab not available: {exc}", flush=True)
        _VOCAB = None
    return _VOCAB


# ---------------------------------------------------------------------------
# Base class
# ---------------------------------------------------------------------------

class CoverCodec(ABC):
    """Abstract base for all cover-protocol codecs."""

    name: str = "base"
    header_overhead: int = 0  # sequencing lives in the cover envelope

    @abstractmethod
    def max_payload_bytes(self) -> int:
        """Maximum payload bytes per single cover message."""
        pass

    @abstractmethod
    def encode(self, data: bytes, part_idx: int, total_parts: int,
               total_len: int = None) -> str:
        """Encode *data* (a raw chunk) into a cover-message string."""
        pass

    @abstractmethod
    def decode(self, cover_text: str) -> bytes:
        """Reverse of *encode*; return the raw payload bytes."""
        pass

    def decode_meta(self, cover_text: str):
        """Return (payload, part_idx, total_parts, total_len)."""
        return self.decode(cover_text), 0, 1, None


# ===========================================================================
# HTTP cover codec
# ===========================================================================

class HttpCoverCodec(CoverCodec):
    name = "http"

    def __init__(self, max_cover_msg: int = 200, fte_mode: bool = False):
        self._max_cover_msg = max_cover_msg
        self._fte_mode = fte_mode
        if fte_mode:
            vocab = _load_fte_vocab()
            self._fte = vocab if vocab else None
            if self._fte:
                self._capacity_bits = self._fte.capacity_bits(self._fte._HTTP_FIELDS)
                self._capacity_bytes = self._fte.capacity_bytes(self._fte._HTTP_FIELDS)
            else:
                self._capacity_bits = 400
                self._capacity_bytes = 50
        else:
            self._fte = None
            self._capacity_bits = 400
            self._capacity_bytes = 50
        self.header_overhead = 0

    def max_payload_bytes(self) -> int:
        return self._capacity_bytes

    _HOSTS = [
        "www.ethereal.com", "pagead2.googlesyndication.com",
        "cerberus", "www.wireshark.org:8080", "127.0.0.1",
    ]
    _UAS = [
        "Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US; rv:1.6) Gecko/20040113",
        "Mozilla/5.0 (X11; U; Linux ppc; rv:1.7.3) Gecko/20041004 Firefox/0.10.1",
        "curl/7.46.0",
        "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:59.0) Gecko/20100101 Firefox/59.0",
    ]
    _ACCEPTS = [
        "text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,",
        "*/*",
        "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    ]
    _ACCEPT_ENCODINGS = ["gzip,deflate", "chunked, gzip", "gzip, deflate"]
    _CONNECTIONS = ["keep-alive", "Keep-Alive", "close"]
    _TARGETS = [
        "/", "/download.html", "/test/ethereal.html", "/foo",
        "/my/path?path=foobar", "/my/foobar", "/?path=g:h",
        "/b/c/d;p?q&path=g:h", "/b/c/d;p?q&path=g",
        "/b/c/g", "/b/c/d;p?q&path=./g", "/b/c/d;p?q&path=g/",
        "/b/c/g/", "/b/c/d;p?q&path=/g", "/g",
        "/b/c/d;p?q&path=//g", "/b/c/d;p?q&path=?y",
        "/b/c/d;p?q&path=g?y", "/b/c/g?y",
        "/b/c/d;p?q&path=", "/b/c/d;p?q&path=;x",
        "/b/c/d;p?q&path=g;x", "/b/c/d;p?q&path=g;x?y",
    ]
    _QUERY_KEYS = sorted([
        "path", "q", "y", "client", "random", "lmt", "format", "output",
        "url", "color_bg", "color_text", "color_link", "color_url", "color_border",
    ])
    _QUERY_VALUES = sorted([
        "foo", "foobar", "g:h", "g", "./g", "g/", "/g", "//g", "?y",
        "g?y", "g;x", "g;x?y", ";x", "",
        "ca-pub-2309191948673629", "1084443430285", "1082467020",
        "468x60_as", "html", "FFFFFF", "333333", "000000", "666633",
    ])

    def encode(self, data: bytes, part_idx: int, total_parts: int,
               total_len: int = None) -> str:
        if self._fte_mode and self._fte is not None:
            return self._encode_fte(data, part_idx, total_parts, total_len)
        return self._encode_b64(data, part_idx, total_parts, total_len)

    def _encode_b64(self, data: bytes, part_idx: int, total_parts: int,
                    total_len: int = None) -> str:
        cap = self.max_payload_bytes()
        payload = data[:cap] if len(data) > cap else data
        b64 = base64.b64encode(payload).decode("ascii")
        host = self._HOSTS[part_idx % len(self._HOSTS)]
        ua = self._UAS[(part_idx + 1) % len(self._UAS)]
        accept = self._ACCEPTS[(part_idx + 2) % len(self._ACCEPTS)]
        lines = [f"GET /?data={b64} HTTP/1.1",
                 f"Host: {host}",
                 f"User-Agent: {ua}",
                 f"Accept: {accept}"]
        if total_parts > 1 or total_len is not None:
            _len = f";len={total_len}" if total_len is not None else ""
            lines.append(f"X-Next: {part_idx + 1}/{total_parts}{_len}")
        lines.append("")
        return "\r\n".join(lines) + "\r\n"

    def _encode_fte(self, data: bytes, part_idx: int, total_parts: int,
                    total_len: int = None) -> str:
        """FTE mode: encode payload bits into observed HTTP field choices."""
        cap = self.max_payload_bytes()
        payload = data[:cap] if len(data) > cap else data

        encoded_fields = self._fte.encode_with_fields(payload, self._fte._HTTP_FIELDS)

        target = encoded_fields.get("http.target", self._TARGETS[0])

        headers = {
            "Host": encoded_fields.get("http.header_value.host", self._HOSTS[0]),
            "User-Agent": encoded_fields.get("http.header_value.user-agent", self._UAS[0]),
            "Accept": encoded_fields.get("http.header_value.accept", self._ACCEPTS[0]),
            "Accept-Encoding": encoded_fields.get("http.header_value.accept-encoding", self._ACCEPT_ENCODINGS[0]),
            "Connection": encoded_fields.get("http.header_value.connection", self._CONNECTIONS[0]),
        }
        for field, default_val in [
            ("http.header_value.accept-language", "en-US,en;q=0.5"),
            ("http.header_value.keep-alive", "300"),
            ("http.header_value.referer", "http://www.ethereal.com/development.html"),
            ("http.header_value.cache-control", "max-age=0, no-cache, no-store"),
        ]:
            val = encoded_fields.get(field)
            if val is not None:
                hdr_name = field.split(".", 2)[2].replace("_", "-").title()
                headers[hdr_name] = val

        query_key = encoded_fields.get("http.query_key", self._QUERY_KEYS[0])
        query_val = encoded_fields.get("http.query_value", self._QUERY_VALUES[0])

        if not target.startswith("/"):
            target = "/" + target
        lines = [f"GET {target} HTTP/1.1"]
        # Query key=value carried in Cookie header (standard HTTP header,
        # avoids ambiguity with ? characters that appear in observed targets)
        lines.append(f"Cookie: {query_key}={query_val}")
        for name, val in headers.items():
            lines.append(f"{name}: {val}")
        if total_parts > 1 or total_len is not None:
            _len = f";len={total_len}" if total_len is not None else ""
            lines.append(f"X-Next: {part_idx + 1}/{total_parts}{_len}")
        lines.append("")
        return "\r\n".join(lines) + "\r\n"

    def decode(self, cover_text: str) -> bytes:
        if self._fte_mode and self._fte is not None:
            return self._decode_fte(cover_text)
        return self._decode_b64(cover_text)

    def _decode_b64(self, cover_text: str) -> bytes:
        m = re.search(r"\?data=([^\s]+)", cover_text)
        if not m:
            return b""
        try:
            return base64.b64decode(m.group(1))
        except Exception:
            return b""

    def _decode_fte(self, cover_text: str) -> bytes:
        encoded = {}

        m = re.match(r"GET\s+(\S+)\s+HTTP/", cover_text)
        if m:
            encoded["http.target"] = m.group(1)

        m = re.search(r"Host:\s*([^\r\n]+)", cover_text)
        if m:
            encoded["http.header_value.host"] = m.group(1).strip()

        m = re.search(r"User-Agent:\s*([^\r\n]+)", cover_text)
        if m:
            encoded["http.header_value.user-agent"] = m.group(1).strip()

        m = re.search(r"Accept:\s*([^\r\n]+)", cover_text)
        if m:
            encoded["http.header_value.accept"] = m.group(1).strip()

        m = re.search(r"Accept-Encoding:\s*([^\r\n]+)", cover_text)
        if m:
            encoded["http.header_value.accept-encoding"] = m.group(1).strip()

        m = re.search(r"Connection:\s*([^\r\n]+)", cover_text)
        if m:
            encoded["http.header_value.connection"] = m.group(1).strip()

        for hdr_name, field_name in [
            ("Accept-Language", "http.header_value.accept-language"),
            ("Keep-Alive", "http.header_value.keep-alive"),
            ("Referer", "http.header_value.referer"),
            ("Cache-Control", "http.header_value.cache-control"),
        ]:
            m = re.search(rf"{hdr_name}:\s*([^\r\n]+)", cover_text)
            if m:
                encoded[field_name] = m.group(1).strip()

        m = re.search(r"Cookie:\s*([^=]+)=([^\r\n]*)", cover_text)
        if m:
            encoded["http.query_key"] = m.group(1).strip()
            encoded["http.query_value"] = m.group(2).strip()

        http_fields = {
            "http.target",
            "http.query_value",
            "http.query_key",
            "http.header_value.host",
            "http.header_value.user-agent",
            "http.header_value.accept",
            "http.header_value.accept-encoding",
            "http.header_value.connection",
            "http.header_value.accept-language",
            "http.header_value.keep-alive",
            "http.header_value.referer",
            "http.header_value.cache-control",
        }
        filtered = {k: v for k, v in encoded.items() if k in http_fields}
        return self._fte.decode_with_fields(filtered, self._fte._HTTP_FIELDS)

    def decode_meta(self, cover_text: str):
        """Return (payload, part_idx, total_parts, total_len)."""
        payload = self.decode(cover_text)
        m = re.search(r"X-Next:\s*(\d+)/(\d+)(?:;len=(\d+))?", cover_text)
        if m:
            return (payload, int(m.group(1)) - 1, int(m.group(2)),
                    int(m.group(3)) if m.group(3) else None)
        return payload, 0, 1, None


# ===========================================================================
# Telnet cover codec
# ===========================================================================

class TelnetCoverCodec(CoverCodec):
    name = "telnet"

    def __init__(self, max_cover_msg: int = 200, fte_mode: bool = False):
        self._max_cover_msg = max_cover_msg
        self._fte_mode = fte_mode
        if fte_mode:
            vocab = _load_fte_vocab()
            self._fte = vocab if vocab else None
            if self._fte:
                self._capacity_bits = self._fte.capacity_bits(self._fte._TELNET_FIELDS)
                self._capacity_bytes = self._fte.capacity_bytes(self._fte._TELNET_FIELDS)
            else:
                self._capacity_bits = 400
                self._capacity_bytes = 50
        else:
            self._fte = None
            self._capacity_bits = 400
            self._capacity_bytes = 50
        self.header_overhead = 0

    def max_payload_bytes(self) -> int:
        return self._capacity_bytes

    def encode(self, data: bytes, part_idx: int, total_parts: int,
               total_len: int = None) -> str:
        if self._fte_mode and self._fte is not None:
            return self._encode_fte(data, part_idx, total_parts, total_len)
        return self._encode_b64(data, part_idx, total_parts, total_len)

    def _encode_b64(self, data: bytes, part_idx: int, total_parts: int,
                    total_len: int = None) -> str:
        cap = self.max_payload_bytes()
        payload = data[:cap] if len(data) > cap else data
        b64 = base64.b64encode(payload).decode("ascii")
        marker = ""
        if total_parts > 1 or total_len is not None:
            _len = f";len={total_len}" if total_len is not None else ""
            marker = f"{part_idx + 1}/{total_parts}{_len};"
        iac = []
        iac.append("\xff\xfb\x01")  # IAC WILL ECHO
        iac.append("\xff\xfb\x03")  # IAC WILL NAWS
        iac.append("\xff\xfa\x18")  # IAC SB 24 (TERMINAL-TYPE)
        iac.append(marker)
        iac.append(b64)
        iac.append("\xff\xf0")  # IAC SE
        return "".join(iac)

    # Telnet option-number <-> name maps (shared by encode/decode)
    _OPT_MAP = {
        "BINARY": 0, "ECHO": 1, "SUPPRESS-GO-AHEAD": 3,
        "STATUS": 5, "TIMING-MARK": 6, "TERMINAL-TYPE": 24,
        "NAWS": 31, "TSPEED": 32, "LFLOW": 33, "LINEMODE": 34,
        "XDISPLOC": 35, "OLD-ENVIRON": 36, "NEW-ENVIRON": 39,
        "AUTHENTICATION": 37, "ENCRYPT": 38,
    }
    _OPT_MAP_REV = {v: k for k, v in _OPT_MAP.items()}
    _CMD_MAP = {"WILL": 0xFB, "WONT": 0xFC, "DO": 0xFD, "DONT": 0xFE}
    _CMD_MAP_REV = {v: k for k, v in _CMD_MAP.items()}

    # The telnet.command vocabulary (from pcap) includes 'SB', which has no
    # standalone IAC command byte.  Encode/decode the 2 command bits by their
    # *index* into a fixed, IAC-representable command set so the bits always
    # round-trip regardless of the observed label at that index.
    _CMD_INDEX_TO_BYTE = {0: 0xFD, 1: 0xFE, 2: 0xFB, 3: 0xFC}  # DO DONT WILL WONT
    _CMD_BYTE_TO_INDEX = {v: k for k, v in _CMD_INDEX_TO_BYTE.items()}

    # subneg_sample fields are serialized as packed indices in the SB payload
    _SUBNEG_SAMPLE_FIELDS = [
        "telnet.subneg_sample.LINEMODE",
        "telnet.subneg_sample.NEW-ENVIRON",
        "telnet.subneg_sample.TERMINAL-TYPE",
        "telnet.subneg_sample.TSPEED",
        "telnet.subneg_sample.XDISPLOC",
    ]

    def _pack_subneg_samples(self, encoded_fields: dict) -> bytes:
        """Pack the chosen subneg_sample field indices into a whole byte."""
        bits = ""
        for f in self._SUBNEG_SAMPLE_FIELDS:
            nbits = self._fte._field_bits.get(f, 0)
            vocab = self._fte._fields.get(f, [])
            chosen = encoded_fields.get(f)
            try:
                idx = vocab.index(chosen) if chosen is not None else 0
            except ValueError:
                idx = 0
            idx = max(0, min(idx, (1 << nbits) - 1)) if nbits else 0
            bits += format(idx, "0%db" % nbits) if nbits else ""
        while len(bits) % 8:
            bits += "0"
        return bytes(int(bits[i:i + 8], 2) for i in range(0, len(bits), 8)) if bits else b"\x00"

    def _unpack_subneg_samples(self, data: bytes) -> dict:
        """Inverse of _pack_subneg_samples."""
        bits = "".join("{:08b}".format(b) for b in data)
        encoded = {}
        pos = 0
        for f in self._SUBNEG_SAMPLE_FIELDS:
            nbits = self._fte._field_bits.get(f, 0)
            vocab = self._fte._fields.get(f, [])
            if nbits and pos + nbits <= len(bits):
                idx = int(bits[pos:pos + nbits], 2)
            else:
                idx = 0
            idx = max(0, min(idx, (1 << nbits) - 1)) if nbits else 0
            if vocab:
                encoded[f] = vocab[min(idx, len(vocab) - 1)]
            pos += nbits
        return encoded

    def _encode_fte(self, data: bytes, part_idx: int, total_parts: int,
                    total_len: int = None) -> str:
        cap = self.max_payload_bytes()
        payload = data[:cap] if len(data) > cap else data
        encoded_fields = self._fte.encode_with_fields(payload, self._fte._TELNET_FIELDS)
        cmd = encoded_fields.get("telnet.command", "DO")
        opt = encoded_fields.get("telnet.option", "ECHO")
        # Encode the 2 command bits by their index into a fixed IAC set.
        cmd_vocab = self._fte._fields.get("telnet.command", [])
        try:
            cmd_idx = cmd_vocab.index(cmd) if cmd is not None else 0
        except ValueError:
            cmd_idx = 0
        cmd_idx = max(0, min(cmd_idx, 3))
        cmd_byte = self._CMD_INDEX_TO_BYTE[cmd_idx]
        opt_num = self._OPT_MAP.get(opt, 1)
        subneg_opt = encoded_fields.get("telnet.subneg_option", "NAWS")
        subneg_opt_num = self._OPT_MAP.get(subneg_opt, 31)

        # Pack the subneg_sample indices into the SB payload (IAC-escaped).
        packed = self._pack_subneg_samples(encoded_fields)
        sb_data = bytearray()
        for b in packed:
            if b == 0xFF:
                sb_data.extend((0xFF, 0xFF))  # IAC escape
            else:
                sb_data.append(b)
        if total_parts > 1 or total_len is not None:
            _len = f";len={total_len}" if total_len is not None else ""
            sb_data.extend(f"{part_idx + 1}/{total_parts}{_len};".encode("ascii"))

        iac = []
        iac.append("\xff" + chr(cmd_byte) + chr(opt_num))
        iac.append("\xff\xfa" + chr(subneg_opt_num))
        iac.append(sb_data.decode("latin-1"))
        iac.append("\xff\xf0")
        return "".join(iac)

    def decode(self, cover_text: str) -> bytes:
        if self._fte_mode and self._fte is not None:
            return self._decode_fte(cover_text)
        return self._decode_b64(cover_text)

    def _decode_b64(self, cover_text: str) -> bytes:
        m = re.search(r"\xff\xfa\x18(.*?)\xff\xf0", cover_text, re.S)
        if not m:
            return b""
        subneg = m.group(1)
        subneg = re.sub(r"^\d+/\d+(?:;len=\d+)?;", "", subneg)
        try:
            return base64.b64decode(subneg)
        except Exception:
            return b""

    def _decode_fte(self, cover_text: str) -> bytes:
        encoded = {}

        # --- IAC command + option byte ---
        i = 0
        n = len(cover_text)
        while i < n - 2:
            if cover_text[i] == "\xff":
                cmd_byte = ord(cover_text[i + 1])
                if cmd_byte == 0xFF:  # escaped literal IAC, skip
                    i += 2
                    continue
                if cmd_byte in self._CMD_BYTE_TO_INDEX:
                    cmd_idx = self._CMD_BYTE_TO_INDEX[cmd_byte]
                    cmd_vocab = self._fte._fields.get("telnet.command", [])
                    if cmd_vocab:
                        encoded["telnet.command"] = cmd_vocab[min(cmd_idx, len(cmd_vocab) - 1)]
                    opt_byte = ord(cover_text[i + 2])
                    encoded["telnet.option"] = self._OPT_MAP_REV.get(opt_byte, "ECHO")
                    i += 3
                    continue
                elif cmd_byte == 0xFA:  # SB: read option then subnegotiation data
                    if i + 2 < n:
                        opt_byte = ord(cover_text[i + 2])
                        encoded["telnet.subneg_option"] = self._OPT_MAP_REV.get(opt_byte, "NAWS")
                        # Collect raw SB data until IAC SE, un-escaping IAC IAC.
                        j = i + 3
                        raw = bytearray()
                        while j < n - 1:
                            if cover_text[j] == "\xff":
                                nxt = ord(cover_text[j + 1])
                                if nxt == 0xF0:  # IAC SE -> end of SB
                                    j += 2
                                    break
                                elif nxt == 0xFF:  # escaped IAC
                                    raw.append(0xFF)
                                    j += 2
                                    continue
                                else:
                                    j += 2
                                    continue
                            raw.append(ord(cover_text[j]))
                            j += 1
                        # First byte(s) = packed subneg_sample indices;
                        # trailing ASCII = sequencing marker (ignored here).
                        packed = bytes(raw[:1]) if raw else b"\x00"
                        encoded.update(self._unpack_subneg_samples(packed))
                        i = j
                        continue
            i += 1

        return self._fte.decode_with_fields(encoded, self._fte._TELNET_FIELDS)

    def decode_meta(self, cover_text: str):
        """Return (payload, part_idx, total_parts, total_len)."""
        payload = self.decode(cover_text)
        m = re.search(r"(\d+)/(\d+)(?:;len=(\d+))?;", cover_text)
        if m:
            return (payload, int(m.group(1)) - 1, int(m.group(2)),
                    int(m.group(3)) if m.group(3) else None)
        return payload, 0, 1, None


def _opt_num_to_name(n: int) -> str:
    """Map a telnet option number to its canonical name."""
    return {
        0: "BINARY", 1: "ECHO", 3: "SUPPRESS-GO-AHEAD",
        5: "STATUS", 6: "TIMING-MARK", 24: "TERMINAL-TYPE",
        31: "NAWS", 32: "TSPEED", 33: "LFLOW", 34: "LINEMODE",
        35: "XDISPLOC", 36: "OLD-ENVIRON", 39: "NEW-ENVIRON",
        37: "AUTHENTICATION", 38: "ENCRYPT",
    }.get(n, "NAWS")


# ===========================================================================
# BBS cover codec
# ===========================================================================

class BBSCoverCodec(CoverCodec):
    """BBS/APRS narrator-based cover codec.

    Wraps a BBS narrator (BBSB7PlusNarrator / APRSNarrator) to produce plausible
    BBS/APRS cover traffic from raw chunk bytes.  Sequencing (part/total) is
    carried by the narrator's own block header ("NN of TT" for 7PLUS); the
    payload round-trips exactly with no internal framing header.

    FTE mode uses an observation-based vocabulary (from bbs_vocab.json)
    to map payload bits into header field choices (command, filename, CRCs,
    status, destination call).  The base64 body carries a plausible filler.
    """

    name = "bbs"

    def __init__(self, max_cover_msg: int = 200, fte_mode: bool = False,
                 src_call: str = "BBS-1", dst_call: str = "BBS-1"):
        self._max_cover_msg = max_cover_msg
        self._fte_mode = fte_mode
        self._src_call = src_call
        self._dst_call = dst_call
        from bbs_narrators import create_narrator_from_env
        self._narrator = create_narrator_from_env(src_call, dst_call)

        if fte_mode:
            # Load BBS observation vocabulary for FTE encoding
            vocab_path = os.path.join(os.path.dirname(__file__), "samples", "bbs_vocab.json")
            try:
                from tools.fte_vocab import FteVocab
                self._bbs_vocab = FteVocab(vocab_path)
                self._capacity_bits = self._bbs_vocab.capacity_bits(self._bbs_vocab._BBS_FIELDS)
                self._capacity_bytes = self._bbs_vocab.capacity_bytes(self._bbs_vocab._BBS_FIELDS)
            except Exception as exc:
                print(f"[BBSCoverCodec] BBS FTE vocab not available: {exc}", flush=True)
                self._bbs_vocab = None
                self._capacity_bits = 400
                self._capacity_bytes = 50
        else:
            self._bbs_vocab = None
            self._capacity_bits = 400
            self._capacity_bytes = max(1, int(max_cover_msg))
        self.header_overhead = 0

    def max_payload_bytes(self) -> int:
        return self._capacity_bytes

    def encode(self, data: bytes, part_idx: int, total_parts: int,
               total_len: int = None) -> str:
        if self._fte_mode and self._bbs_vocab is not None:
            return self._encode_fte(data, part_idx, total_parts, total_len)
        return self._narrator.format_packet(
            data, is_small_ctrl=False, part=part_idx + 1, total=total_parts
        )

    # Plausible filler for the 7PLUS base64 body (ZIP file header + padding)
    _FILLER_B64 = base64.b64encode(
        b"PK\x03\x04\x14\x00\x08\x00\x08\x00" + b"\x00" * 32
    ).decode("ascii")

    def _encode_fte(self, data: bytes, part_idx: int, total_parts: int,
                    total_len: int = None) -> str:
        """FTE mode: encode payload bits into observed BBS field choices."""
        cap = self.max_payload_bytes()
        payload = data[:cap] if len(data) > cap else data

        encoded_fields = self._bbs_vocab.encode_with_fields(payload, self._bbs_vocab._BBS_FIELDS)

        cmd = encoded_fields.get("bbs.command", "FILES")
        filename = encoded_fields.get("bbs.filename", "SYSUPD01.ZIP")
        file_crc = encoded_fields.get("bbs.file_crc", "0000")
        block_crc = encoded_fields.get("bbs.block_crc", "0000")
        status = encoded_fields.get("bbs.status", "7PLUS extraction complete - file saved")
        dst_call = encoded_fields.get("bbs.dst_call", self._dst_call)

        part = part_idx + 1
        total = total_parts if total_parts > 1 else 1

        # Carry total_len in the 5-digit size field (normally "00512") so the
        # receiver can truncate the final partial chunk's FTE padding.
        size_field = f"{total_len:05d}" if total_len is not None else "00512"

        # Build a plausible 7PLUS BBS session: command line + data block
        lines = [
            cmd,
            f" go_7+. {part:02d} of {total:02d} {filename} {size_field} {file_crc}",
            "M" + self._FILLER_B64,
            status,
            f" stop_7+. ({file_crc}/{block_crc})",
            f"de {dst_call}>",
        ]
        return "\r".join(lines) + "\r"

    def decode(self, cover_text: str) -> bytes:
        if self._fte_mode and self._bbs_vocab is not None:
            return self._decode_fte(cover_text)
        decoded = self._narrator.decode_packet(cover_text)
        return decoded if decoded is not None else b""

    def _decode_fte(self, cover_text: str) -> bytes:
        encoded = {}

        # Line 0: command
        lines = cover_text.split("\r")
        if lines:
            encoded["bbs.command"] = lines[0].strip()

        # Parse the go_7+ header line: " go_7+. NN of TT filename SIZE file_crc"
        for line in lines:
            m = re.match(r" go_7\+\.\s+(\d+)\s+of\s+(\d+)\s+(\S+)\s+\d+\s+([0-9A-F]{4})", line)
            if m:
                encoded["bbs.filename"] = m.group(3)
                encoded["bbs.file_crc"] = m.group(4)
                break

        # Parse status line and stop line
        for line in lines:
            if line.startswith("***"):
                encoded["bbs.status"] = line.strip()
                break
            if "extraction complete" in line:
                encoded["bbs.status"] = "7PLUS extraction complete - file saved"
                break

        # Parse block CRC from stop line
        for line in lines:
            m = re.match(r" stop_7\+\.\s+\(([0-9A-F]{4})/([0-9A-F]{4})\)", line)
            if m:
                encoded["bbs.block_crc"] = m.group(2)
                break

        # Parse de CALL> line
        for line in lines:
            m = re.match(r"de (\S+)>$", line)
            if m:
                encoded["bbs.dst_call"] = m.group(1)
                break

        return self._bbs_vocab.decode_with_fields(encoded, self._bbs_vocab._BBS_FIELDS)

    def decode_meta(self, cover_text: str):
        if self._fte_mode and self._bbs_vocab is not None:
            payload = self._decode_fte(cover_text)
        else:
            decoded = self._narrator.decode_packet(cover_text)
            if decoded is None:
                return b"", 0, 1, None
            payload = decoded

        # 7PLUS data blocks carry "NN of TT" in their header.
        m = re.search(r"go_7\+\.\s+(\d+)\s+of\s+(\d+)", cover_text)
        if m:
            # Extract total_len from the 5-digit size field that follows
            # the filename (e.g. "00512" for no truncation, or "00012" for 12 bytes).
            size_m = re.search(r"\s(\d{5})", cover_text)
            total_len = int(size_m.group(1)) if size_m else None
            return payload, int(m.group(1)) - 1, int(m.group(2)), total_len
        # APRS / control formats have no part counter -> single message.
        return payload, 0, 1, None


# ===========================================================================
# Rotating cover codec
# ===========================================================================

class RotatingCoverCodec(CoverCodec):
    """Alternate cover protocols per frame.

    The protocol is identified on receive from the cover text itself, so no
    prefix byte is added to the payload (which would otherwise overflow the
    smallest member codec's capacity in FTE mode).
    """

    name = "rotate"

    def __init__(self, protocols=None, interval: int = 1,
                 max_cover_msg: int = 200, fte_mode: bool = False):
        self.protocols = protocols or ["http", "telnet", "bbs"]
        self.codecs = [
            get_codec(p, max_cover_msg=max_cover_msg, fte_mode=fte_mode)
            for p in self.protocols
        ]
        self._by_name = {c.name: c for c in self.codecs}
        self.interval = max(1, interval)
        self._frame_counter = 0
        self.header_overhead = 0

    def max_payload_bytes(self) -> int:
        return min(c.max_payload_bytes() for c in self.codecs)

    def encode(self, data: bytes, part_idx: int, total_parts: int,
               total_len: int = None) -> str:
        proto_idx = (self._frame_counter // self.interval) % len(self.codecs)
        codec = self.codecs[proto_idx]
        cover = codec.encode(data, part_idx, total_parts, total_len)
        self._frame_counter += 1
        return cover

    def decode(self, cover_text: str) -> bytes:
        return self.decode_meta(cover_text)[0]

    def _detect_order(self, cover_text: str):
        """Return member codecs in most-likely-first order for this text."""
        order = []
        if "\xff" in cover_text and "telnet" in self._by_name:
            order.append(self._by_name["telnet"])
        if re.match(r"GET\s+\S+\s+HTTP/", cover_text) and "http" in self._by_name:
            order.append(self._by_name["http"])
        if "bbs" in self._by_name:
            order.append(self._by_name["bbs"])
        # Append any remaining codecs as a fallback.
        for c in self.codecs:
            if c not in order:
                order.append(c)
        return order

    def decode_meta(self, cover_text: str):
        for codec in self._detect_order(cover_text):
            try:
                payload, part_idx, total_parts, total_len = codec.decode_meta(cover_text)
            except Exception:
                continue
            if payload:
                return payload, part_idx, total_parts, total_len
        return b"", 0, 1, None


# ---------------------------------------------------------------------------
# Codec factory
# ---------------------------------------------------------------------------

def get_codec(proto: str, max_cover_msg: int = 200, fte_mode: bool = False) -> CoverCodec:
    """Return a CoverCodec instance for the given protocol name."""
    proto = proto.lower()
    if proto == "http":
        return HttpCoverCodec(max_cover_msg=max_cover_msg, fte_mode=fte_mode)
    if proto == "telnet":
        return TelnetCoverCodec(max_cover_msg=max_cover_msg, fte_mode=fte_mode)
    if proto == "rotate":
        return RotatingCoverCodec(protocols=["http", "telnet", "bbs"],
                                  interval=1,
                                  max_cover_msg=max_cover_msg,
                                  fte_mode=fte_mode)
    if proto == "bbs":
        return BBSCoverCodec(max_cover_msg=max_cover_msg, fte_mode=fte_mode)

    class _UnknownCodec(CoverCodec):
        name = "unknown"

        def max_payload_bytes(self):
            return 2 ** 31

        def encode(self, data, part_idx, total_parts, total_len=None):
            return data

        def decode(self, cover_text):
            return cover_text

    return _UnknownCodec()


def split_payload(data: bytes, max_payload: int) -> list:
    if len(data) <= max_payload:
        return [data]
    chunks = []
    idx = 0
    while idx < len(data):
        chunks.append(data[idx:idx + max_payload])
        idx += max_payload
    return chunks