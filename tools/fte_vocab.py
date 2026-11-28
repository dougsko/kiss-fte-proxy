#!/usr/bin/env python3
"""
Observation-based FTE vocabulary encoder/decoder.

Reads the observation vocabulary from samples/vocab_all.json and provides
bit-level encoding/decoding by mapping payload bits into per-field choices
from observed traffic.  Capacity S = sum_i log2(|gamma_i|) bits per message,
matching the paper's Theorem 1 model.

Both sender and receiver share the same vocabulary; the field order is
deterministic (fixed list below).

Usage:
    from tools.fte_vocab import FteVocab
    v = FteVocab('samples/vocab_all.json')
    encoded = v.encode_with_fields(payload_bytes, HTTP_FIELDS)
    decoded = v.decode_with_fields(encoded, HTTP_FIELDS)
    bits = v.capacity_bits(HTTP_FIELDS)
"""
import json
import math
import sys
from collections import OrderedDict


def load_vocab(path: str) -> dict:
    """Load the observation vocabulary JSON and return per-field value lists."""
    with open(path, "r") as fh:
        data = json.load(fh)
    return data


class FteVocab:
    """
    Observation-based FTE vocabulary.

    Maps payload bits into choices of observed field values per the paper's
    capacity model: S = sum_i log2(|gamma_i|) bits per message.

    Codec-specific field sets can be passed to encode_with_fields() /
    decode_with_fields() so that HTTP codecs only use HTTP fields and
    Telnet codecs only use Telnet fields.
    """

    # ------------------------------------------------------------------
    # Field ordering – must match what the receiver expects
    # ------------------------------------------------------------------
    _HTTP_FIELDS = [
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
    ]

    _TELNET_FIELDS = [
        "telnet.option",
        "telnet.command",
        "telnet.subneg_option",
        "telnet.subneg_sample.LINEMODE",
        "telnet.subneg_sample.NEW-ENVIRON",
        "telnet.subneg_sample.TERMINAL-TYPE",
        "telnet.subneg_sample.TSPEED",
        "telnet.subneg_sample.XDISPLOC",
    ]

    # BBS FTE fields – observation-based vocabulary learned from BBS narrator
    # output (7PLUS file-transfer blocks) plus BPQ BBS user commands.
    _BBS_FIELDS = [
        "bbs.command",
        "bbs.filename",
        "bbs.file_crc",
        "bbs.block_crc",
        "bbs.status",
        "bbs.dst_call",
    ]

    _ALL_FIELDS = _HTTP_FIELDS + _TELNET_FIELDS

    def __init__(self, vocab_path: str):
        data = load_vocab(vocab_path)
        self._fields = OrderedDict()   # name -> sorted list of observed values
        self._field_bits = {}          # name -> floor(log2(cardinality))

        loaded = set()
        # Load the canonical field sets in deterministic order first.
        for name in self._ALL_FIELDS:
            if name in data["fields"]:
                counts = data["fields"][name]
                values = sorted(counts.keys())
                self._fields[name] = values
                n = len(values)
                self._field_bits[name] = int(math.log2(n)) if n > 1 else 0
                loaded.add(name)
            else:
                self._fields[name] = []
                self._field_bits[name] = 0

        # Load any additional fields present in the vocab (e.g. bbs.*) that
        # are not part of _ALL_FIELDS.  These can be referenced explicitly by
        # callers via encode_with_fields(fields=...) / decode_with_fields(...).
        for name in data["fields"]:
            if name not in loaded:
                counts = data["fields"][name]
                values = sorted(counts.keys())
                self._fields[name] = values
                n = len(values)
                self._field_bits[name] = int(math.log2(n)) if n > 1 else 0

    # ---- capacity ------------------------------------------------------------------
    def capacity_bits(self, fields=None) -> int:
        """Total FTE capacity in bits per message for the given *fields*."""
        if fields is None:
            fields = list(self._fields.keys())
        return sum(self._field_bits.get(name, 0) for name in fields if name in self._fields)

    def capacity_bytes(self, fields=None) -> int:
        """Total FTE capacity in whole bytes per message."""
        return self.capacity_bits(fields) // 8

    # ---- encode ----------------------------------------------------------------------
    def encode_with_fields(self, data: bytes, fields) -> dict:
        """
        Encode *data* using only the specified *fields*.

        The bit-stream of *data* is consumed sequentially; each field
        consumes floor(log2(|gamma_i|)) bits and the corresponding observed
        value is returned.  Padding zeros fill remaining capacity.
        """
        bit_str = "".join(f"{b:08b}" for b in data)
        total_bits = len(bit_str)
        encoded = {}
        pos = 0

        for field_name in fields:
            if field_name not in self._fields:
                continue
            vocab = self._fields[field_name]
            nbits = self._field_bits[field_name]
            if nbits == 0:
                continue

            if pos + nbits <= total_bits:
                index_str = bit_str[pos:pos + nbits]
            else:
                remaining = total_bits - pos
                index_str = bit_str[pos:] + ("0" * (nbits - remaining)) if remaining > 0 else ("0" * nbits)

            index = int(index_str, 2) if index_str else 0
            card = len(vocab)
            if card <= 1:
                pos += nbits
                continue
            index = min(index, card - 1)

            chosen = vocab[index]
            encoded[field_name] = chosen
            pos += nbits

        return encoded

    def encode(self, data: bytes) -> dict:
        """Encode *data* using all fields (HTTP + Telnet)."""
        return self.encode_with_fields(data, list(self._fields.keys()))

    # ---- decode ----------------------------------------------------------------------
    def decode_with_fields(self, encoded: dict, fields) -> bytes:
        """
        Reverse of *encode_with_fields*: extract the bit-stream from chosen
        observed values (only for the specified *fields*), then convert back
        to bytes.
        """
        bit_parts = []

        for field_name in fields:
            if field_name not in self._fields:
                continue
            vocab = self._fields[field_name]
            nbits = self._field_bits[field_name]
            if nbits == 0:
                continue

            chosen = encoded.get(field_name)
            try:
                idx = vocab.index(chosen) if chosen is not None else 0
            except ValueError:
                idx = 0
            idx = max(0, min(idx, (1 << nbits) - 1))

            for bit_pos in range(nbits - 1, -1, -1):
                bit = (idx >> bit_pos) & 1
                bit_parts.append(str(bit))

        if not bit_parts:
            return b""

        bit_str = "".join(bit_parts)
        nbytes = len(bit_str) // 8
        result = bytearray()
        for i in range(nbytes):
            chunk = bit_str[i * 8:(i + 1) * 8]
            result.append(int(chunk, 2))

        return bytes(result)

    def decode(self, encoded: dict) -> bytes:
        """Reverse of *encode*: decode using all fields."""
        return self.decode_with_fields(encoded, list(self._fields.keys()))


def main():
    import pathlib
    vocab_path = pathlib.Path(__file__).resolve().parent.parent / "samples" / "vocab_all.json"
    if not vocab_path.exists():
        print(f"Vocabulary not found at {vocab_path}", file=sys.stderr)
        sys.exit(1)

    v = FteVocab(str(vocab_path))
    print(f"FTE Vocabulary loaded from {vocab_path}")
    print(f"Total fields: {len(v._fields)}")
    print(f"HTTP capacity: {v.capacity_bits(v._HTTP_FIELDS)} bits ({v.capacity_bytes(v._HTTP_FIELDS)} bytes)")
    print(f"Telnet capacity: {v.capacity_bits(v._TELNET_FIELDS)} bits ({v.capacity_bytes(v._TELNET_FIELDS)} bytes)")
    print(f"All capacity: {v.capacity_bits()} bits ({v.capacity_bytes()} bytes)")
    print()
    print("HTTP fields:")
    for name in v._HTTP_FIELDS:
        nbits = v._field_bits[name]
        card = len(v._fields[name])
        print(f"  {name}: cardinality={card}, bits={nbits}")
    print("Telnet fields:")
    for name in v._TELNET_FIELDS:
        nbits = v._field_bits[name]
        card = len(v._fields[name])
        print(f"  {name}: cardinality={card}, bits={nbits}")


if __name__ == "__main__":
    main()