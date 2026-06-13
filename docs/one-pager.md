# mcap-encrypt — Project One-Pager

**GitHub:** [remete618/mcap-encrypt](https://github.com/remete618/mcap-encrypt) | **README:** [README.md](https://github.com/remete618/mcap-encrypt/blob/main/README.md) | **API reference:** [docs/api.md](https://github.com/remete618/mcap-encrypt/blob/main/docs/api.md) | **Foxglove integration:** [docs/foxglove.md](https://github.com/remete618/mcap-encrypt/blob/main/docs/foxglove.md)

---

## What this is

A public-key encryption library for MCAP robotics logs. Encrypt a recording with one or more public keys; only the matching private key can decrypt. Three protection levels: data only, data plus metadata, or full file encryption. Works in Go, TypeScript, and Python. Ships a CLI and a Foxglove Studio bridge.

---

## Origin

In early 2022, Foxglove engineer **Wyatt Alt** (`wkalt`) opened [foxglove/mcap PR #9](https://github.com/foxglove/mcap/pull/9), a proposal for per-channel encryption that would have added `key_id` and encryption fields to channel records. It was closed on **February 10, 2022** with the note: "closing — out of near-term scope."

A few years later, the same question came up again: how do you share MCAP logs with an analyst, a vendor, or a cloud service without exposing raw sensor data? No solution existed. This project is the answer.

---

## What it does

Three encryption levels, each a superset of the previous:

1. **Data only** — chunk payloads encrypted; topic names, timestamps, and schema definitions remain readable. Safe to index in Foxglove without a key.
2. **Data + metadata** — same as above, plus Metadata record values encrypted. Map content is opaque; record names stay visible.
3. **Full encryption** — data, metadata values, and metadata names all encrypted. Maximum opacity.

Any file can have multiple recipients. A single encrypted file can be decrypted by Alice, Bob, and a CI service using three different private keys, without re-encrypting. Key rotation re-wraps the symmetric key for new recipients without touching chunk ciphertext.

---

## Foxglove bridge

The library ships a built-in bridge that mirrors `foxglove-bridge` for live ROS 2 robots, but for encrypted files.

```
mcap-encrypt bridge --key analyst.priv.pem recording.mcap
# → ws://localhost:8765
```

Connect Foxglove Studio to `ws://localhost:8765`. All topics, panels, and timeline scrubbing work identically to a live robot feed. No decrypted file is ever written to disk. The private key never leaves the machine.

| | foxglove-bridge | mcap-encrypt bridge |
|---|---|---|
| Data source | Live ROS 2 | Encrypted MCAP file |
| Protocol | Foxglove WebSocket v1 | Foxglove WebSocket v1 |
| Studio connection | ws://localhost:8765 | ws://localhost:8765 |
| Key required | No | Yes |
| Decrypted file on disk | n/a | Never |

---

## Technical shape

- **Algorithms:** XChaCha20-Poly1305 (data), RSA-4096-OAEP or X25519-HKDF (key wrapping)
- **Languages:** Go (reference), TypeScript (Node + browser), Python
- **Cross-language:** any key or encrypted file produced by one implementation works with all others; verified by 8 automated interop tests on every CI push
- **Format:** backward-compatible; standard MCAP readers skip encrypted opcodes gracefully
- **Tests:** 85+ Go unit tests, 4 fuzz targets, 80 TypeScript tests, 37 Python tests, 8 interop tests
- **Security findings fixed:** INT-2025-001, INT-2025-002, INT-2025-003 (all found by fuzzing, all resolved)

---

## Current status

Feature-complete for single-user and multi-recipient workflows. Not yet externally audited. Not published to pkg.go.dev, npm, or PyPI under a stable release tag.

**Done:**
- Encrypt, decrypt, key rotation, inspection
- Multi-recipient (RSA and X25519)
- Encrypted attachments and metadata
- Foxglove bridge
- Python library
- Streaming encrypt (disk-based two-pass, O(1) RAM)
- Seekable summary section (timeline display without decryption)

**Not done yet:**
- External security audit (v1.0 gate)
- Conformance test vectors (interop without running code)
- SSH key support (`~/.ssh/id_ed25519.pub` as a recipient)
- GitHub Action for CI encrypt/decrypt
- KMS/HSM backend
- Stable npm and PyPI releases

---

## Open strategic questions

**Where should this live?**
Currently under a personal GitHub account (`remete618/mcap-encrypt`). Moving it into the Foxglove org is unlikely: Foxglove would inherit liability for a security-critical library it did not build and has not audited. The realistic options are: contributing it upstream to the `foxglove/mcap` repo (where the original 2022 PR was proposed, closes the loop on that conversation), spinning it out as a dedicated open-source org (neutral, credible home), or keeping it independent under the personal account until v1.0 and an external audit justify the move.

**Should Foxglove adopt it?**
The bridge already speaks the same WebSocket protocol as `foxglove-bridge`. The npm package already exports `iterateMessages()`. Three integration paths exist, with very different effort and ownership:

| | Path 1 (client-side) | Path 2 (server-side) | Bridge |
|---|---|---|---|
| Who does the work | Foxglove frontend eng | Foxglove infra + security | Already done |
| Where key lives | User's browser session | Foxglove KMS/HSM | User's local machine |
| Decrypted data goes | Foxglove Studio (browser) | Foxglove cloud pipeline | RAM only, never disk |
| Foxglove involvement | Yes, 1-2 weeks | Yes, 4-6 weeks | Zero |
| Works today | No | No | Yes |

The bridge requires zero Foxglove engineering. Path 1 is a Studio UI integration (detect encrypted file, prompt for key, call `iterateMessages()`). Path 2 requires key management infrastructure. The library side is complete for all three paths.

**Current bridge limitation:** decrypts the full file to disk then loads all messages into RAM. Works well for typical recordings under ~5 GB. Streaming decrypt (serve chunks on demand as Studio scrubs the timeline) is on the roadmap but not yet built.

**Should this project continue?**
The 2022 PR was closed as out of scope. The problem it addresses has not gone away. Robotics teams shipping to defense, healthcare, and automotive increasingly need provable access control on sensor data. This project is the only public implementation of chunk-level MCAP encryption with multi-recipient support and a Foxglove-native bridge.

**What would v1.0 require?**
An external audit, conformance vectors, and a stable release tag on all three package registries. Estimated effort: 4 to 6 weeks with one focused engineer.

---

*Weekend project. Built by someone from marketing. 85+ tests pass, fuzz targets caught three security issues before anyone saw the code. If that's impressive or concerning — depends on your threat model 🥸*

*Built by Radu Marginean. Questions: radu@foxglove.dev or eyepaq.com*
