# Stage 03: AES Loader + Jigsaw Encoding

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

A shellcode loader that introduces **two independent protection layers** — the first stage with multi-layer defense:
- **RC4 stream cipher** (mislabeled "AES") with custom envelope: nonce derivation, counter-mode PRGA, integrity verification
- **Jigsaw fragmentation** — encrypted payload split into 64-byte chunks, interleaved with English text padding, Fisher-Yates shuffled
- Same PEB-walking API resolver (additive hash, InLoadOrderModuleList)
- Heap scrubbing after shellcode copy (write_volatile)
- Executes a MessageBox("GoodBoy") as proof of execution

**This binary achieved 0/76 on VirusTotal** (March 2026, all 76 AV engines clean).

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Entropy normalization via payload fragmentation | Multi-scale entropy variance analysis |
| RC4 mislabeled as "AES" — analyst misdirection | Recognizing non-standard crypto despite naming |
| Jigsaw encoding to defeat ML section entropy features | YARA rules for permutation map patterns |
| Multi-layer protection (obfuscation + encryption) | Distinguishing obfuscation layers from encryption layers |
| Heap scrubbing with write_volatile | Memory forensics — finding shellcode after scrub |
| Custom integrity hash (modified FNV) | Identifying non-standard hash seeds in disassembly |

---

## What's New vs Stage 02

| Concept | Stage 02 Taught | Stage 03 Adds |
|---------|----------------|---------------|
| Encryption | XOR (trivially breakable) | RC4 stream cipher (keystream depends on entire key) |
| Entropy | High entropy island in .rdata | Normalized ~6.0 via jigsaw fragmentation |
| Protection layers | 1 (crypto only) | 2 (jigsaw obfuscation + RC4 crypto) |
| Integrity | None | FNV variant hash with custom seed + finalizer |
| Nonce | None | Key-derived 12-byte nonce (wrong key = early reject) |
| Crypto misdirection | — | Module named "AES" but uses RC4 |
| Detection target | XOR loop patterns | Permutation map arrays in .rdata |
| New attack surface | — | The jigsaw map IS a YARA-detectable structure |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **~1,200 lines** of guided analysis — entropy theory, jigsaw mechanics, crypto internals, PIC shellcode anatomy, forwarded exports, detection engineering, adversarial challenges |
| `aes-loader.exe` | The compiled binary (~290 KB, Rust, PE64) — open in Ghidra/x64dbg and follow along |

---

## Quick Start

1. **Complete Stages 01-02 first** — this stage builds directly on XOR cryptanalysis and entropy concepts
2. **Download** `aes-loader.exe` and `LEARNING_PATH.md`
3. **Open** `LEARNING_PATH.md` and follow Section 1 (Theory: The Entropy Problem)
4. **Analyze** the jigsaw structure in Ghidra (Section 2: Static Analysis)
5. **Reverse** the custom crypto (Section 3: The Crypto Layer)
6. **Trace** the multi-layer pipeline (Section 4)
7. **Write** detection rules (Section 8: Detection Engineering)

---

## The Gate Architecture

```
main()
  |
  +-- Gate 1: init_app_config()     -- benign code mass (BTreeMap, HashSet, file I/O)
  |     +-- FAIL -> silent exit
  |
  +-- Gate 2: verify_env()          -- 5 environment variable checks (BTreeMap)
  |     +-- FAIL -> silent exit
  |
  +-- Gate 3: preflight()           -- 5 more env checks (HashMap + fs::read_dir)
  |     +-- FAIL -> silent exit
  |
  +-- Gate 4: PEB.BeingDebugged     -- inline anti-debug check
  |     +-- FAIL -> silent exit
  |
  +-- Gate 5: sandbox_check()       -- CPU/RAM/disk/uptime hardware metrics
  |     +-- FAIL -> silent exit
  |
  +-- Payload execution:
        jigsaw_decode -> RC4 decrypt (nonce + integrity verify)
        -> VirtualAlloc(RW) -> copy -> scrub heap
        -> VirtualProtect(RX) -> CreateThread -> MessageBox("GoodBoy")
```

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Hash Algorithm | Additive hash (seed `0x1F2E3D4C`, mul `0x1003F`) |
| PEB List | InLoadOrderModuleList |
| Encryption | RC4 with custom envelope (mislabeled "AES") |
| Integrity | FNV variant (seed `0x27D4EB2F`, extra `h ^= h >> 16`) |
| Nonce | 12-byte key-derived (FNV seed `0x14650FB0739D0383`) |
| Jigsaw | 64-byte chunks, FNV-1a seeded PRNG, Fisher-Yates shuffle |
| Shellcode | 302-byte MessageBox("GoodBoy","OK") + ExitProcess via block_api |
| Encrypted size | 318 bytes (12 nonce + 302 ciphertext + 4 integrity) |
| Jigsaw payload | 640 bytes (5 data + 5 padding chunks, 10-entry map) |
| Memory | W^X discipline (PAGE_READWRITE -> PAGE_EXECUTE_READ) |
| Anti-forensic | Heap buffer zeroed after copy via write_volatile |
| Binary Size | ~290 KB |
| VT Score | 0/76 achieved (March 2026) |

---

## The Multi-Layer Pipeline

```
BUILD TIME (tools/encrypt_03.py):
  shellcode (302 bytes)
    → patch ExitThread → ExitProcess
    → RC4_encrypt(key)
    → nonce[12] || ciphertext[302] || integrity[4] = 318 bytes
    → jigsaw_encode()
    → shuffled_payload (640 bytes) + map (10 entries)

RUNTIME (aes-loader.exe):
  JIGSAW_PAYLOAD + JIGSAW_MAP
    → jigsaw_decode() → 318 bytes
    → nonce verify (wrong key = early reject)
    → integrity verify (tampered data = reject)
    → RC4_decrypt(key) → 302 bytes shellcode
    → VirtualAlloc(RW) → copy → scrub → VirtualProtect(RX) → CreateThread
```

---

## Course Progression

This is **Stage 03** of 15:

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03 (this)   Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

| Stage | Technique | What's New |
|-------|-----------|------------|
| 01 | Basic Loader | XOR decrypt, PEB-walk, VirtualAlloc->VirtualProtect->CreateThread |
| 02 | XOR Cryptanalysis | Known-plaintext attack, IC key-length detection, memory scrubbing |
| **03** | **AES + Jigsaw** | **Entropy normalization, payload fragmentation, RC4 stream cipher, integrity verification** |
| 04 | API Hashing | Deep dive into PEB internals, rainbow tables |
| 05 | APC Injection | Early Bird, cross-process execution |
| 06 | Variant Analysis | Same technique, different keys — family clustering |
| 07 | Direct Syscalls | The name is a lie — and that's the lesson |
| 08 | Indirect Syscalls | Call stack forensics, gadget scanning |
| 09 | Anti-Debug | 7 techniques: PEB, NtQueryInfo, RDTSC, hardware breakpoints |
| 10 | Anti-Sandbox | Hardware fingerprinting, weighted scoring |
| 11 | Persistence | Registry Run key, scheduled tasks, COM hijacking |
| 12 | Module Stomping | Overwrite legitimate DLL .text section |
| 13 | Sleep Obfuscation | Encrypt payload during sleep |
| 14 | Combined Loader | 8-layer evasion stack |
| 15 | C2 Agent | Full command-and-control with encrypted HTTPS beaconing |

---

## Safety

> **EDUCATIONAL USE ONLY**

- This binary is a proof-of-concept for authorized security training, research, and CTF competitions
- **Payload**: `MessageBox("GoodBoy")` — pops a harmless dialog box, then exits
- No network activity, no persistence, no system modifications
- **WRITE** code on your host machine. **EXECUTE** only in isolated VMs

**Do NOT submit this binary to VirusTotal** — doing so trains AV engines against it (see "sample burning" in the Learning Path).

---

## Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Windows 10/11 x64 VM | Execution environment | [FlareVM](https://github.com/mandiant/flare-vm) recommended |
| Ghidra 11.x | Static analysis / disassembly | [ghidra-sre.org](https://ghidra-sre.org/) |
| x64dbg | Dynamic analysis / debugging | [x64dbg.com](https://x64dbg.com/) |
| ScyllaHide | Anti-anti-debug plugin for x64dbg | [GitHub](https://github.com/x64dbg/ScyllaHide) |
| Python 3.10+ | Crypto verification scripts, entropy analysis | [python.org](https://python.org/) |
| PE-bear | PE structure viewer | [GitHub](https://github.com/hasherezade/pe-bear) |

**Recommended VM Configuration** (for Gate 5 — sandbox detection to pass):
- 4+ CPU cores
- 8+ GB RAM
- 100+ GB disk
- Let the VM run for 30+ minutes before executing the binary
- Screen resolution 1920x1080 or higher

---

## About the Goodboy Framework

A comprehensive malware development & analysis course with:
- **15 progressive stages** from basic loader to full C2 agent
- **Dual perspective** — every technique taught from both offense and defense
- **Empirical AV/ML evasion data** from testing against 76+ antivirus engines
- **Production-grade Rust code** — not toy demos
- **CTF challenges** for each stage (competitive format)

All 15 binaries achieved 0/76 on VirusTotal. The course documents not just HOW to achieve this, but also what happens AFTER — the sample burning phenomenon, the ML arms race, and why the act of testing IS the burn.

---

## License

This material is provided for educational purposes in authorized security training, research, penetration testing, and CTF competitions. Not for unauthorized access or operational deployment against systems without explicit written permission.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
