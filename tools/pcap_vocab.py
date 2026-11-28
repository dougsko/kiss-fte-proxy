#!/usr/bin/env python3
"""
Extract observation-based FTE vocabularies from pcap captures.

Reads classic pcap (Ethernet/IPv4/TCP), reassembles directional TCP streams,
then mines HTTP message fields and Telnet IAC negotiation structures.

Outputs JSON with per-field observation counts + capacity estimate:
    S = sum_i log2(|gamma_i|) bits per message

Usage:
    python3 tools/pcap_vocab.py pcap/*.pcap pcap/*.cap > vocab.json
"""
import json
import struct
import subprocess
import sys
import tempfile
from collections import Counter, defaultdict

MAGICS = {
    b"\xd4\xc3\xb2\xa1": ("<", 1e-6),
    b"\xa1\xb2\xc3\xd4": (">", 1e-6),
    b"\x4d\x3c\xb2\xa1": ("<", 1e-9),
    b"\xa1\xb2\x3c\x4d": (">", 1e-9),
}


def maybe_convert_pcapng(path):
    """If *path* is a pcapng file, convert it to a classic pcap using tcpdump.

    Returns the (possibly new) path to a classic pcap file.
    """
    with open(path, "rb") as fh:
        magic = fh.read(4)
    if magic == b"\x0a\x0d\x0d\x0a":  # pcapng magic
        with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tf:
            tmp = tf.name
        result = subprocess.run(
            ["tcpdump", "-r", path, "-w", tmp],
            capture_output=True,
            text=True,
        )
        if result.returncode == 0:
            return tmp
        else:
            print(f"Warning: tcpdump failed to convert {path}: {result.stderr}",
                  file=sys.stderr)
            return path
    return path


def read_pcap(path):
    """Yield (ts, linktype, frame_bytes) for classic pcap. Skips pcapng."""
    with open(path, "rb") as fh:
        hdr = fh.read(24)
        if len(hdr) < 24 or hdr[:4] not in MAGICS:
            raise ValueError(f"{path}: not a classic pcap (pcapng? convert with tcpdump -w)")
        endian, tsres = MAGICS[hdr[:4]]
        _, _, _, _, _, linktype = struct.unpack(endian + "HHiIII", hdr[4:24])
        while True:
            rec = fh.read(16)
            if len(rec) < 16:
                return
            ts_s, ts_us, caplen, origlen = struct.unpack(endian + "IIII", rec)
            data = fh.read(caplen)
            if len(data) < caplen:
                return
            yield ts_s + ts_us * tsres, linktype, data


def parse_ipv4_tcp(frame, linktype):
    if linktype != 1:  # DLT_EN10MB
        return None
    if len(frame) < 14:
        return None
    ethertype = struct.unpack("!H", frame[12:14])[0]
    off = 14
    while ethertype in (0x8100, 0x88A8):  # VLAN tags
        if len(frame) < off + 4:
            return None
        ethertype = struct.unpack("!H", frame[off + 2:off + 4])[0]
        off += 4
    if ethertype != 0x0800:
        return None
    ip = frame[off:]
    if len(ip) < 20:
        return None
    ihl = (ip[0] & 0x0F) * 4
    if ip[9] != 6:
        return None
    tot = struct.unpack("!H", ip[2:4])[0]
    src = ".".join(str(b) for b in ip[12:16])
    dst = ".".join(str(b) for b in ip[16:20])
    tcp = ip[ihl:tot]
    if len(tcp) < 20:
        return None
    doff = (tcp[12] >> 4) * 4
    seq = struct.unpack("!I", tcp[4:8])[0]
    flags = tcp[13]
    payload = tcp[doff:]
    sport, dport = struct.unpack("!HH", tcp[0:4])
    return dict(src=src, dst=dst, sport=sport, dport=dport, seq=seq,
                flags=flags, payload=payload)


def reassemble(path):
    """Return {(src,sport,dst,dport): stream_bytes}."""
    segs = defaultdict(dict)  # key -> rel_seq -> bytes
    bases = {}
    for ts, linktype, frame in read_pcap(path):
        p = parse_ipv4_tcp(frame, linktype)
        if not p or not p["payload"]:
            continue
        if p["flags"] & 0x02:  # SYN consumes a seq number
            pass
        key = (p["src"], p["sport"], p["dst"], p["dport"])
        seq = p["seq"] + 1 if p["flags"] & 0x02 else p["seq"]
        base = bases.setdefault(key, seq)
        rel = (seq - base) & 0xFFFFFFFF
        if rel > 0x7FFFFFFF:  # wrapped/old retransmit from before capture
            continue
        segs[key][rel] = p["payload"]
    out = {}
    for key, parts in segs.items():
        buf = bytearray()
        end = 0
        for rel in sorted(parts):
            if rel > end:
                buf.extend(b"\x00" * (rel - end))  # gap marker
            chunk = parts[rel]
            if rel + len(chunk) <= end:
                continue
            buf.extend(chunk[max(0, end - rel):])
            end = rel + len(chunk)
        out[key] = bytes(buf)
    return out


# ---------------- HTTP ----------------
HTTP_VERSIONS = ("HTTP/1.1", "HTTP/1.0", "HTTP/2")
METHODS = {"GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "TRACE", "CONNECT", "PATCH"}
HDR_RE = None


def parse_http_headers(block):
    """Parse a header block into (first_line, [(name, value), ...])."""
    lines = block.split(b"\r\n")
    if not lines:
        return None, []
    try:
        first = lines[0].decode("latin-1")
    except Exception:
        return None, []
    hdrs = []
    for raw in lines[1:]:
        if not raw or b":" not in raw:
            continue
        name, _, val = raw.partition(b":")
        hdrs.append((name.decode("latin-1").strip(), val.decode("latin-1").strip()))
    return first, hdrs


def mine_http(stream, vocab):
    # Only consider streams that look like HTTP
    if b"HTTP/" not in stream[:8192] and b"\r\n\r\n" not in stream[:8192]:
        return 0
    n = 0
    pos = 0
    while True:
        idx = stream.find(b"\r\n\r\n", pos)
        if idx < 0:
            break
        block = stream[pos:idx]
        pos = idx + 4
        first, hdrs = parse_http_headers(block)
        if not first:
            continue
        parts = first.split(" ")
        if len(parts) >= 2 and parts[0] in METHODS and parts[2:3] and parts[2].startswith("HTTP/"):
            vocab["http.method"][parts[0]] += 1
            vocab["http.request_version"][parts[2]] += 1
            target = parts[1]
            vocab["http.target"][target] += 1
            if "?" in target:
                # Extract both keys and values from query string
                for kv in target.split("?", 1)[1].split("&"):
                    k, _, v = kv.partition("=")
                    # Extract key (truncate to 40 chars for consistency)
                    vocab["http.query_key"][k[:40]] += 1
                    # Extract value (truncate to 80 chars for consistency)
                    if v:
                        vocab["http.query_value"][v[:80]] += 1
        elif parts[0].startswith("HTTP/") and len(parts) >= 2:
            vocab["http.response_version"][parts[0]] += 1
            vocab["http.status"][parts[1]] += 1
            vocab["http.reason"][" ".join(parts[2:])[:40]] += 1
        else:
            continue
        n += 1
        for name, val in hdrs:
            vocab["http.header_name"][name] += 1
            vocab[f"http.header_value.{name.lower()}"] [val[:80]] += 1
    return n


# ---------------- Telnet ----------------
TELNET_CMDS = {251: "WILL", 252: "WONT", 253: "DO", 254: "DONT", 250: "SB", 240: "SE", 255: "IAC"}
TELNET_OPTS = {
    0: "BINARY", 1: "ECHO", 3: "SUPPRESS-GO-AHEAD", 5: "STATUS", 6: "TIMING-MARK",
    24: "TERMINAL-TYPE", 31: "NAWS", 32: "TSPEED", 33: "LFLOW", 34: "LINEMODE",
    35: "XDISPLOC", 36: "OLD-ENVIRON", 39: "NEW-ENVIRON", 37: "AUTHENTICATION",
    38: "ENCRYPT",
}


def mine_telnet(stream, vocab):
    if b"\xff" not in stream:
        return 0
    n = 0
    i = 0
    while i < len(stream) - 1:
        if stream[i] != 0xFF:
            i += 1
            continue
        cmd = stream[i + 1]
        if cmd == 0xFF:  # escaped literal
            i += 2
            continue
        name = TELNET_CMDS.get(cmd)
        if name in ("WILL", "WONT", "DO", "DONT") and i + 2 < len(stream):
            opt = stream[i + 2]
            vocab["telnet.command"][name] += 1
            vocab["telnet.option"][TELNET_OPTS.get(opt, f"OPT-{opt}")] += 1
            n += 1
            i += 3
        elif cmd == 250 and i + 2 < len(stream):
            opt = stream[i + 2]
            end = stream.find(b"\xff\xf0", i + 3)
            if end < 0:
                break
            payload = stream[i + 3:end]
            vocab["telnet.command"]["SB"] += 1
            vocab["telnet.subneg_option"][TELNET_OPTS.get(opt, f"OPT-{opt}")] += 1
            # subneg payload first octet / printable sample
            if payload:
                vocab[f"telnet.subneg_sample.{TELNET_OPTS.get(opt, opt)}"][payload[:24].hex()] += 1
            n += 1
            i = end + 2
        else:
            i += 2
    return n


def capacity(vocab):
    import math
    rows = []
    total = 0.0
    for field, counts in sorted(vocab.items()):
        card = len(counts)
        bits = math.log2(card) if card > 1 else 0.0
        total += bits
        rows.append((field, card, round(bits, 2), sum(counts.values())))
    return round(total, 2), rows


def main(paths):
    vocab = defaultdict(Counter)
    per_file = {}
    temp_files = []
    for path in paths:
        converted = maybe_convert_pcapng(path)
        if converted != path:
            temp_files.append(converted)
        try:
            streams = reassemble(converted)
        except ValueError as exc:
            print(f"skip {path}: {exc}", file=sys.stderr)
            continue
        h = t = 0
        for (src, sport, dst, dport), stream in streams.items():
            if not stream:
                continue
            if 80 in (sport, dport) or 8080 in (sport, dport) or b"HTTP/" in stream[:64]:
                h += mine_http(stream, vocab)
            if 23 in (sport, dport) or b"\xff\xfb" in stream or b"\xff\xfd" in stream:
                t += mine_telnet(stream, vocab)
        per_file[path] = {"http_messages": h, "telnet_cmds": t, "streams": len(streams)}
    for tmp in temp_files:
        try:
            import os
            os.unlink(tmp)
        except OSError:
            pass
    total_bits, rows = capacity(vocab)
    print(json.dumps({
        "per_file": per_file,
        "capacity_bits_per_message": total_bits,
        "fields": {f: dict(c) for f, c in vocab.items()},
        "summary": [{"field": f, "cardinality": c, "bits": b, "observations": o}
                    for f, c, b, o in rows],
    }, indent=2))


if __name__ == "__main__":
    main(sys.argv[1:] or ["pcap/http.cap"])
