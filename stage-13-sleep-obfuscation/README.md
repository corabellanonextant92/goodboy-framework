# Stage 13: Sleep Obfuscation — Encrypting Payloads Between Heartbeats

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

The first stage with **temporal evasion** — the payload encrypts itself during sleep, making it invisible to periodic memory scanners 95%+ of the time:

```
Decrypt shellcode → VirtualProtect(RX)
  ┌─ Loop 3 cycles:
  │   VirtualProtect(RW) → XOR encrypt with SLEEP_KEY
  │   Sleep(50ms)         → scanner sees random data
  │   XOR decrypt         → restore shellcode
  │   VirtualProtect(RX)  → ready for execution
  └─
CreateThread → execute
```

During Sleep, memory scanners see: encrypted random bytes in a RW region. The plaintext shellcode exists only for microseconds between cycles.

Plus 7 evasion gates inherited from Stages 09-12.

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| XOR encrypt/decrypt during VirtualProtect permission cycling | ETW VirtualProtect monitoring for RX↔RW cycling |
| Separate SLEEP_KEY from payload decryption key | Memory entropy scanning (encrypted vs plaintext states) |
| Why 95% scanner miss rate (detection probability math) | YARA rules for permission cycling + sleep patterns |
| Direct Sleep() IAT import (benign, no apihash) | 4-layer defense hardening guide |
| Inline XOR vs common library RC4 (evasion trade-off) | Python: VProtect cycling detector, entropy scanner, cycle reconstructor |

---

## What's New vs Stages 01-12

| Concept | Stages 01-12 | Stage 13 |
|---------|-------------|----------|
| Memory during sleep | Plaintext RX (always scannable) | **Encrypted RW (invisible to scanners)** |
| Permission cycling | One-time RW→RX transition | **Repeated RX→RW→RX cycles per sleep** |
| Temporal evasion | None | **Payload visible only during execution, encrypted during idle** |
| Sleep key | N/A | **Separate 16-byte SLEEP_KEY (different from payload XOR_KEY)** |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,254 lines** — Sleep obfuscation deep dive, detection probability math, 2 YARA rules, Sigma rule, 3 Python scripts, defense hardening, adversarial challenges |
| `sleep-obfuscation.exe` | The compiled binary (~380 KB, Rust, PE64) — 3 encrypt→sleep→decrypt cycles |

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (uses common library for anti-debug + apihash) |
| Technique | XOR encrypt payload during sleep, VirtualProtect RX↔RW cycling |
| Sleep Cycles | 3 cycles × 50ms each |
| Sleep Key | 16-byte key (separate from payload decryption key) |
| API Resolution | 5 execution APIs via apihash + direct Sleep() IAT import |
| Anti-Debug | 7 techniques via common library (from Stage 09) |
| Sandbox Detection | 5 hardware checks, threshold ≥ 3 (from Stage 10) |
| Shellcode | 302-byte MessageBox("GoodBoy"), XOR encrypted |
| Binary Size | ~380 KB |

---

## Course Progression

This is **Stage 13** of 15 — a **HARD** stage.

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13 (this)
```

---

## Safety

> **EDUCATIONAL USE ONLY**

- **Payload**: `MessageBox("GoodBoy")` — harmless
- **Sleep cycles**: 3 × 50ms (150ms total, then executes)
- **EXECUTE** only in isolated VMs

---

## About the Goodboy Framework

15-stage progressive Windows malware development & analysis course.

## License

Educational purposes only. Not for unauthorized access or operational deployment.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
