# Protocol Compliance Plan — kiss-fte-proxy

## 1. Scope & Baseline

The current `kiss-fte-proxy` implements a **KISS ↔ TCP** transparent bridge that forwards raw AX.25 UI frames between an upstream KISS application and Direwolf/TNC KISS port. It adds:
- Chunking into 110-byte plaintext blocks (MAX_PLAINTEXT_CHUNK)
- Base64 encoding → BBS-style `go_7+/stop_7+` narration (BBSBaseNarrator: `bbs7plus` or `aprs`)
- KISS escaping/unescaping (FEND/FESC handling)
- AX.25 UI framing with 2‑address header, PID 0xF0, control 0x03
- A 4‑byte sequencing header (msg_id idx total) per chunk
- Reassembly with time‑out and max‑pending guard

**The paper (arXiv:2002.10687v2, Oakley et al.)** describes an **FTE‑based covert channel** that tunnels TCP through a protected static protocol (Synchrophasor/PMU) using:
1. **Observation‑based FTE** — learn per‑field vocabularies from real traffic, encode bits as choices of observed values; capacity S = Σ log₂(|γᵢ|).
2. **Deterministic HMM timing** — infer inter‑packet delay states from a histogram of real traffic; generate matching timing to evade side‑channel analysis; compare via KS test and χ² state‑wise equality.
3. **Protocol compliance / undetectability** — synthetic traffic is syntactically equivalent to the host protocol (field values are drawn from observed sets), so rule‑based/DPI signatures produce false positives on legitimate traffic; inter‑packet timings follow the same distribution, so timing‑side‑channel detection fails.

The repo currently **does not implement** any of the FTE or HMM mechanisms; payloads pass through unmodified in base64, and inter‑packet delays are uncontrolled (back‑to‑back `sendall`).

The goal of this plan is to make the proxy **more protocol‑compliant** in the paper's sense: output traffic should be syntactically valid, observation‑based, and timing‑compatible with the host KISS/AX.25/Direwolf protocol so that rule‑based DPI, stateful protocol analysis, and statistical/side‑channel analysis all fail to distinguish it from legitimate traffic.

---

## 2. Gaps vs. Paper‑Compliant Protocol Proxy

| Gap | Current repo behavior | Paper‑compliant behavior required |
|---|---|---|
| **Observation‑based FTE** | Payload bytes pass through base64‑encoded → high‑entropy, non‑protocol‑conformant; detectable by statistical/rule analysis. | Sample real KISS/AX.25/Direwolf traffic (callsign SSID patterns, PID 0xF0 prevalence, control 0x03, BBS narrator field distributions); encode payload bits as choices from those observed vocabularies; each packet’s fields draw from the shared out‑of‑band lookup table. |
| **Deterministic HMM timing** | No inter‑packet delay modeling; frames emitted as fast as socket buffers allow → detectable side‑channel timing fingerprint. | Capture real inter‑packet delay samples from Direwolf KISS sessions; build a deterministic HMM (states = histogram peaks, transition probs = normalized counts, output symbols = delay values); when forwarding chunks, emit delays drawn from the HMM to match the statistical profile of legitimate traffic (KS p‑value > 0.05 against reference distribution). |
| **Stateful protocol analysis** | Session is a single persistent TCP→KISS pipe; no connect/ack/disc state, no poll/keepalive; a stateful firewall could flag missing handshake transitions. | At minimum ensure every KISS data frame carries correct command 0x00 on port 0; optionally add session‑setup KISS commands (0x01 connect, 0x02 disconnect) that obey Direwolf state machine; avoid sending illegal command byte combos that a stateful inspector could flag. |
| **Rule‑based / DPI detection** | Base64-wrapped payload with arbitrary seq header; the BBS “go_7+/stop_7+” pattern is distinctive; rule‑based signatures could match it. | All field values (callsigns, PID, control, APRS/7+ format) must be drawn from observed vocabularies; the BBS narrator format can stay but the *payload* inside should be observation‑based encoded, not random base64; also embed FTE‑encoded data such that any rule matching fixed patterns would also match legitimate traffic, producing false positives. |
| **Inter‑packet timing compliance** | No pacing; back‑to‑back sends. | After each chunk send, insert a delay sampled from the real KISS/AX.25 inter‑frame gap distribution (e.g., exponential with measured mean, or the HMM‑derived model). The goal: χ² test between generated gap histogram and reference passes (p > 0.05). |
| **Frame syntactic correctness** | KISS escaping correct; AX.25 UI lacks FCS (Direwolf adds it on transmit) — acceptable but not documented; seq header is 4 arbitrary bytes appended to each chunk after base64 decode, total payload > 255 bytes when base64‑expanded may exceed AX.25 info‑field limit if not capped. | Verify that after base64 decode + 4‑byte header, total ≤ 255 info bytes (Direwolf AX.25 max) – currently MAX_PLAINTEXT_CHUNK=110 works because base64(110)+4 ≈ 148 < 255; ensure this invariant holds for any enlarged chunk size supporting more FTE capacity. Document that FCS is omitted (Direwolf adds it). |

---

## 3. Concrete Implementation Steps

### 3.1. Observation‑based FTE Pipeline

1. **Traffic capture** – add a helper script `tools/capture_kiss_traffic.py` that runs Direwolf KISS in a test harness and records a pcap of ~10 k real KISS data frames (or use provided samples). Parse each frame: extract callsign SSIDs, PID, control, A‑field/b‑field patterns, and the raw information field (if any). Store per‑field frequency tables.
2. **Build lookup tables** – from the frequency tables create per‑field observation lists γᵢ:
   - `callsign_src.ssid` list (most common: 0, 9)
   - `callsign_dst.ssid` list
   - `pid` list (≈ 0xF0 ~ 90 % of UI frames)
   - `control` list (≈ 0x03 UI)
   - optional: BBS narrator field tokens if we want to encode within the narrator text itself.
3. **FTE encoder** – modify `kiss-bbs-fte.py` `encode_ft` (new function):
   - Given raw payload bits, for each field position decide how many bits can be encoded using `log₂(|γᵢ|)`.
   - Replace the chosen field value with the γᵢ entry at index = (encoded_bits % |γᵢ|) (or a systematic mapping).
   - If payload bits exceed combined capacity, split across multiple fields/packets.
   - Ensure the resulting frame still passes `unwrap_ax25_ui` + `kiss_unescape` validation (i.e., field bytes stay within valid ranges).
4. **FTE decoder** – symmetric: read the chosen γᵢ indices, map back to bits; reconstruct original payload.
5. **Integrate with existing chunking** – the 4‑byte sequencing header stays; the payload that goes into each chunk is first FTE‑encoded, then base64‑encoded for the BBS narrator (or the narrator can embed the encoded bytes directly if format permits).

### 3.2. Deterministic HMM Timing Model

1. **Parse real inter‑packet delays** – from the same capture in 3.1, compute `Δᵢ = timestampᵢ₊₁ − timestampᵢ` for consecutive KISS data frames (ignore control frames). Plot histogram; identify peak groups (likely 3–5 states as in the paper's Fig 7).
2. **Fit deterministic HMM** – using the algorithm from the paper (count bigrams of labeled states; transition prob a→b = count(ab)/count(a)). Produce a 3‑state HMM (adjustable) with states {S₁,S₂,S₃} and output delay symbols.
3. **Timing emitter** – wrap the `app_to_tnc` and `tnc_to_app` loops:
   - Maintain a last‑send timestamp per direction.
   - Before each `sendall`, compute elapsed since last send; if less than the HMM‑sampled minimum delay, `time.sleep` the difference.
   - Sample the next delay from the HMM given the current state; transition to next state per HMM probabilities.
   - Optionally expose env vars `HMM_STATES` (e.g., `3`) and `HMM_MODEL_PATH` to load a pre‑computed pickle.
4. **Validation** – after a test run, compute the gap histogram of generated traffic; run two‑sample KS test against the reference capture histogram; require p > 0.05.

### 3.3. Protocol‑Compliant KISS/AX.25 Hardening

| Change | Rationale |
|---|---|
| **Document FCS omission** – add a comment & env var `INCLUDE_FCS=0|1`; default 0 (Direwolf adds FCS). | Makes the framing contract explicit; prevents future confusion when someone reads the PCAP. |
| **Add TXDELAY pacing** – optional env `KISS_TXDELAY_MS` (default 0); when set, `time.sleep(delay/1000)` after each `sendall`. | Reduces back‑to‑back burstiness that stateful analysis could flag; also gives a knob to match real TNC inter‑frame spacing. |
| **Validate KISS command byte** – in `read_kiss_frames`, currently only yields frames with `raw_frame[0] & 0x0F == 0x00`. Add optional logging of other command bytes (connect 0x01, set mode 0x03, etc.) for debugging; ensure they are not silently dropped without notice. | Aligns with KISS spec compliance; a stateful inspector expecting a full command sequence would not see unexpected drops. |
| **AX.25 frame size guard** – after base64 decode+4‑byte header, assert `len(payload) <= 255`; if exceeded, split further. | Guarantees the AX.25 info field never overflows; prevents Wireshark/KISS errors. |
| **Callsign SSID sanity** – in `encode_ax25_addr`, currently just ljust/pad; optionally validate that SSID ∈ {0,9} (most common) when FTE is active, to keep observed-field invariant. | Keeps the callsign field within the observed vocabulary, aiding observation‑based FTE stealth. |

### 3.4. Test & Compliance Suites (extending `tests/`)

Add the following test categories (parallel to existing `test-e2e.sh` vectors):

| Test | Description |
|---|---|
| **FTE‑capacity test** – encode increasing payload sizes (1 B, 10 B, 100 B, 1 KB) and verify decode round‑trip success; also verify that the encoded field choices stay within the pre‑computed observation vocabularies (i.e., no out‑of‑range indices). |
| **KS‑timing test** – capture a reference Direwolf KISS session pcap, compute gap histogram, run a generated‑traffic gap histogram through KS test; fail if p ≤ 0.05. |
| **χ²‑HMM state test** – compute state‑wise χ² statistic between generated and reference HMMs; fail if any state’s χ² exceeds critical value at α = 0.05. |
| **DPI‑rule false‑positive test** – define a set of simple rule patterns (e.g., "base64 block longer than 40 chars", "PID != 0xF0"), count how many generated frames match vs. a baseline of real traffic; the generated rate should be ≤ the baseline rate (i.e., not worsen detectability). |
| **Payload‑size regression** – ensure `MAX_PLAINTEXT_CHUNK` combined with base64 + 4‑byte header never exceeds 255 info bytes; auto‑adjust if changed. |
| **Backward‑compatibility e2e** – keep all existing test vectors passing (small ACK, 32/33‑byte boundary, 110/111‑byte boundary, all 256 byte values, 10 KiB random, escape‑heavy). These must still succeed with FTE+HMM enabled (the FTE encoding should be lossless). |

### 3.5. Documentation & Configuration Updates

- Add a `FTE` section to `README.md` describing how to enable observation‑based FTE (env vars: `FTE_ENABLE=1`, `FTE_VOCAB_PATH`, `HMM_MODEL_PATH`).
- Update `quadlet/kiss-fte-proxy.env.example` with new optional vars: `FTE_ENABLE`, `FTE_VOCAB_PATH`, `HMM_STATES`, `KISS_TXDELAY_MS`.
- Add a `PLAN-protocol-compliance.md` (this file) to the repo root for future maintainers.

---

## 4. Success Criteria (what "more protocol compliant" means)

1. **Round‑trip FTE losslessness** – any payload up to the capacity limit S = Σ log₂(|γᵢ|) bits can be encoded and decoded without byte corruption.
2. **Statistical indistinguishability** – generated traffic passes KS test (p > 0.05) against real KISS/AX.25 inter‑packet delay distribution and χ² HMM state‑wise test against reference model.
3. **Rule‑based DPI resistance** – a static rule set matching current proxy output (base64 blocks, go_7+/stop_7+ markers) yields a false‑positive rate on generated traffic no higher than on a corpus of real KISS traffic; in practice, the observation‑based encoded fields should make such rules produce many false positives on legitimate traffic, which is the desired effect.
4. **Stateful protocol compliance** – every emitted KISS frame carries a valid command byte (0x00 data on port 0); no illegal frame sequences are produced; a stateful inspector following the KISS state machine would not encounter unexpected states.
5. **Backward compatibility** – all existing e2e test vectors in `tests/` continue to pass unchanged.

---

## 5. Rough Order-of-Effort Estimate

| Task | Estimated person‑days |
|---|---|
| Traffic capture & vocab build (script + data) | 2 |
| FTE encoder/decoder integration | 3 |
| HMM timing model (parse, fit, emit) | 3 |
| KISS/AX.25 hardening & documentation | 1 |
| Test extensions (5 new test categories) | 2 |
| Total | ~11 person‑days (can be staggered; most scripts are I/O‑bound and can be done in parallel). |

---

## 6. Next Immediate Steps

1. **Create a traffic capture directory** `samples/` with a small (≈ 1 min) real Direwolf KISS capture (pcap) – or use the provided test harness pcap if available.
2. **Parse the capture** to produce per‑field frequency tables; store as JSON (e.g., `samples/vocab.json`).
3. **Prototype the FTE encoder** that simply swaps a few payload bytes into the observed SSID fields (low‑risk first step) and verify round‑trip.
4. **Add timing delays** using a simple exponential distribution keyed by a config; run a quick e2e and record gap histogram.
5. **Iterate** toward full KS/χ² compliance, then merge into `main` after all test categories pass.

---

*End of Plan.*