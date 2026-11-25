# KISS BBS FTE end-to-end test (Podman)

This harness runs two copies of `ghcr.io/dougsko/direwolf:latest`, two copies of the proxy, and a transparent KISS bridge. It uses Dire Wolf's `KISSCOPY` feature to copy frames between KISS clients attached to each Dire Wolf instance. The bridge connects as a KISS client to both TNCs and forwards data frames between them.

**No sound devices, modem audio, WAV capture, or RF simulation are used.** Dire Wolf is exercised as a KISS/AX.25 packet endpoint. This validates the proxy's BBS transformation, AX.25 UI wrapping, KISS framing, Dire Wolf KISS client interfaces, bridge forwarding, and reverse reassembly. It does not validate over-the-air modulation, demodulation, RF timing, or FCS behavior.

## Run

Requires Podman and a Compose-independent Podman CLI. From this directory:

```bash
./tests/test-e2e.sh
```

The script builds the proxy image, pulls `ghcr.io/dougsko/direwolf:latest`, starts all containers on a private Podman network, runs the test vectors, writes results, and removes containers/network on exit.

Artifacts are retained in `artifacts/`:

- `transport.pcap` — standalone PCAP with `LINKTYPE_AX25_KISS` (16). It contains the KISS command byte followed by the unescaped AX.25 frame, so Wireshark can decode the AX.25 packet content.
- `results.txt` — byte-for-byte test results.

## Test vectors

Small ACK-style payloads, the 32/33-byte format boundary, 110/111-byte chunk boundary, 1 KiB, all 256 byte values, 10 KiB random data, and KISS escape-heavy data.

## Notes

- The proxy in `proxy/kiss-bbs-fte.py` is based on upstream commit `8d9e3cd`, with environment-based endpoint/callsign configuration and a fix to inspect the KISS command byte (`raw_frame[0]`). It also validates chunk bounds and caps pending reassemblies.
- `KISSCOPY` is the Dire Wolf facility that lets KISS clients attached to one Dire Wolf instance exchange packets. The bridge uses two Dire Wolf instances, so packets traverse both TNC KISS interfaces.
- The bridge does not parse AX.25 or BBS contents. It only parses KISS framing, forwards KISS data frames, and records the same AX.25 bytes to PCAP.
- The PCAP is an inspection artifact only. It is not replayed and is not required for test success.
- If `ADEVICE null null` is unsupported by the particular ALSA build/runtime, Dire Wolf may need a harmless ALSA null PCM configuration; no audio is routed or used by the test.
