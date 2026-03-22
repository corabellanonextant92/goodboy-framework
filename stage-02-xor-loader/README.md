# Stage 02: XOR Cryptanalysis & Memory Forensics

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

A shellcode loader identical in architecture to Stage 01, with a **different XOR key** — designed to teach you how to **break XOR encryption regardless of the key**:
- Same shellcode staging pipeline (decrypt → allocate → protect → execute)
- Same PEB-walking API resolver (additive hash, InLoadOrderModuleList)
- **Different 16-byte XOR key** — proves changing the key defeats signature detection but NOT cryptanalysis
- Introduces **memory scrubbing** — heap buffer zeroed after shellcode copy
- Executes a MessageBox("GoodBoy") as proof of execution

**This binary achieved 0/76 on VirusTotal** (March 2026, all 76 AV engines clean).

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Why changing the key is trivially cheap | Known-plaintext attack to recover ANY XOR key |
| Memory scrubbing as anti-forensic technique | Index of Coincidence for key length detection |
| Benign code gates for ML classifier evasion | Shannon entropy to classify XOR vs RC4 vs AES |
| VT Submission Paradox — why testing IS the burn | Key-agnostic shellcode scanner (works on ANY XOR key) |
| Rolling XOR as a stronger variant | YARA rules for XOR loop patterns (not key-specific) |
| ExitProcess vs ExitThread (forwarded export pitfall) | Memory forensics — finding shellcode after heap scrub |

---

## What's New vs Stage 01

| Concept | Stage 01 Taught | Stage 02 Adds |
|---------|----------------|---------------|
| XOR encryption | How to identify it | How to **break** it (known-plaintext, IC, entropy) |
| Detection rules | YARA for specific hash/key constants | YARA for XOR **loop patterns** (key-independent) |
| Sigma rules | Basic RW→RX transition | Extended with **memory scrub** indicator |
| Memory forensics | — | Heap scrubbing analysis + VirtualProtect shortcut |
| Cipher comparison | — | XOR vs RC4 cryptanalytic comparison table |
| Adversarial thinking | Break YARA/Sigma/pe-sieve | Break known-plaintext/IC/entropy attacks |
| Operational security | — | VT Submission Paradox + session burning |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,238 lines** of guided analysis — cryptanalysis theory, 8 hands-on exercises, Python scripts, YARA/Sigma rules, rolling XOR challenge, adversarial countermeasures |
| `xor-loader.exe` | The compiled binary (~285 KB, Rust, PE64) — open in Ghidra/x64dbg and follow along |

---

## Quick Start

1. **Complete Stage 01 first** — this stage builds directly on those concepts
2. **Download** `xor-loader.exe` and `LEARNING_PATH.md`
3. **Open** `LEARNING_PATH.md` and follow Section 1 (Theory: Why XOR Persists)
4. **Break** the encryption in Sections 2-3 (Static + Dynamic Analysis)
5. **Write** key-agnostic detection rules (Section 4: Detection Engineering)
6. **Compare** XOR vs RC4 cryptanalysis (Section 5)
7. **Build** a rolling XOR variant and find its bug (Section 6)

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
        XOR decrypt -> VirtualAlloc(RW) -> copy -> zero heap
        -> VirtualProtect(RX) -> CreateThread -> MessageBox("GoodBoy")
```

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Hash Algorithm | Additive hash (seed `0x1F2E3D4C`, mul `0x1003F`) |
| PEB List | InLoadOrderModuleList |
| Encryption | XOR with 16-byte repeating key (`0x29, 0x3a, 0xf7, 0xbb...`) |
| Shellcode | 302-byte MessageBox("GoodBoy","OK") + ExitProcess via block_api |
| Memory | W^X discipline (PAGE_READWRITE → PAGE_EXECUTE_READ) |
| Anti-forensic | Heap buffer zeroed after copy to executable region |
| Binary Size | ~285 KB |
| VT Score | 0/76 achieved (March 12, 2026) |

---

## The Learning Path Includes

### Theory (Section 1)
- Why XOR persists in 50%+ of commodity malware despite being trivially breakable
- XOR vs RC4 vs AES trade-off matrix (code size, speed, analyst resistance)
- Real-world examples: Hackmosphere Defender bypass, VENON trojan, EMBER2024 dataset

### Cryptanalysis Exercises (Section 2)
- **Exercise 1**: Shannon entropy calculation — hands-on Python, XOR vs AES entropy gap
- **Exercise 2**: Index of Coincidence — detect key length=16 without seeing the key
- **Exercise 3**: Known-plaintext attack — recover key[0] from E9 prologue, full key recovery via frequency analysis on larger payloads
- **Exercise 4**: XOR loop vs RC4 PRGA recognition in disassembly

### Memory Forensics (Section 3)
- **Exercise 5**: Watch heap scrubbing in x64dbg — two copies → one copy
- **Exercise 6**: VirtualProtect shortcut — scrubbing is irrelevant for live debugging

### Detection Engineering (Section 4)
- YARA rule: XOR loop byte patterns (key-independent, works across all XOR variants)
- Sigma rule: Extended with memory scrub indicator
- **Exercise 7**: Build a key-agnostic shellcode scanner in Python

### Comparative Cryptanalysis (Section 5)
- **Exercise 8**: XOR vs RC4 — complete attack comparison table (known-plaintext, IC, frequency, brute force)

### Build Your Own (Section 6)
- Rolling XOR challenge — CBC-like chaining mode
- Bug hunt: byte 0 leaks in plaintext (discover + fix)
- Adversarial countermeasures: defeat your own cryptanalysis (3 attack/defense pairs)

### Evasion Engineering (Section 6C)
- VT Submission Paradox — why checking if binary A is clean makes binary B detectable
- Agent.ION forensic analysis — how ESET generalized across 20+ submissions
- Session burning mechanics

### Knowledge Check (Section 7)
- 5 questions testing entropy, IC, memory scrubbing, known-plaintext, runtime key generation

---

## Course Progression

This is **Stage 02** of 15:

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01          Stage 04          Stage 07          Stage 14
  Stage 02 (this)   Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

| Stage | Technique | What's New |
|-------|-----------|------------|
| 01 | Basic Loader | XOR decrypt, PEB-walk, VirtualAlloc→VirtualProtect→CreateThread |
| **02** | **XOR Cryptanalysis** | **Known-plaintext attack, IC key-length detection, entropy classification, memory scrubbing** |
| 03 | AES + Jigsaw | Entropy normalization, payload fragmentation |
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
- No network activity, no file writes (except %TEMP% breadcrumbs), no persistence, no system modifications
- **WRITE** code on your host machine. **EXECUTE** only in isolated VMs

**Do NOT submit this binary to VirusTotal** — doing so trains AV engines against it (see "VT Submission Paradox" in the Learning Path).

---

## Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Windows 10/11 x64 VM | Execution environment | [FlareVM](https://github.com/mandiant/flare-vm) recommended |
| Ghidra 11.x | Static analysis / disassembly | [ghidra-sre.org](https://ghidra-sre.org/) |
| x64dbg | Dynamic analysis / debugging | [x64dbg.com](https://x64dbg.com/) |
| ScyllaHide | Anti-anti-debug plugin for x64dbg | [GitHub](https://github.com/x64dbg/ScyllaHide) |
| Python 3.10+ | Cryptanalysis scripts, entropy calculation | [python.org](https://python.org/) |
| PE-bear | PE structure viewer | [GitHub](https://github.com/hasherezade/pe-bear) |
| xortool (optional) | Automated XOR key recovery | `pip install xortool` |

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
