# Stage 01: Basic Shellcode Loader

> Part of the **Goodboy Framework** — a 15-stage progressive Windows malware development & analysis course written in Rust.

## What This Is

A fully functional shellcode loader that:
- Decrypts an embedded XOR-encrypted payload at runtime
- Resolves Windows APIs dynamically via PEB-walking (no suspicious imports)
- Allocates executable memory with W^X discipline (RW→RX, never RWX)
- Executes a MessageBox("GoodBoy") as proof of execution
- Passes through 5 evasion gates before reaching the payload

**This binary achieved 0/76 on VirusTotal** (March 2026, all 76 AV engines clean).

---

## What You'll Learn

| Red Team | Blue Team |
|----------|-----------|
| Shellcode staging pipeline | VirtualAlloc→VirtualProtect→CreateThread detection |
| PEB-walking API hashing | Rainbow table construction to reverse hash constants |
| XOR encryption for payload obfuscation | Known-plaintext attacks against XOR |
| Anti-sandbox hardware checks | Sysmon/ETW detection rules |
| Anti-debug (PEB.BeingDebugged) | ScyllaHide bypass techniques |
| ML classifier evasion engineering | YARA rule writing for hash-based resolvers |

---

## Files

| File | Description |
|------|-------------|
| `LEARNING_PATH.md` | **1,649 lines** of guided analysis — theory, hands-on exercises, Python scripts, YARA/Sigma rules, detection engineering, adversarial thinking challenges |
| `basic-loader.exe` | The compiled binary (278 KB, Rust, PE64) — open in Ghidra/x64dbg and follow along with the Learning Path |
| `SAFETY.md` | Lab safety guidelines — WRITE code on host, EXECUTE only in VMs |

---

## Quick Start

1. **Download** `basic-loader.exe` and `LEARNING_PATH.md` from [Releases](../../releases)
2. **Set up** a Windows 10/11 VM with Ghidra + x64dbg + ScyllaHide + Python 3.10+
3. **Open** `LEARNING_PATH.md` and follow Section 1 (Theory)
4. **Analyze** the binary in Ghidra (Section 2: Static Analysis)
5. **Debug** in x64dbg (Section 3: Dynamic Analysis)
6. **Write** YARA + Sigma detection rules (Section 4: Detection Engineering)
7. **Build** your own XOR encryptor (Section 5: Build Your Own)

---

## The 5-Gate Architecture

```
main()
  |
  +-- Gate 1: verify_env()         -- 5 environment variable checks (BTreeMap)
  |     +-- FAIL -> silent exit
  |
  +-- Gate 2: preflight()          -- 5 more env checks (HashMap + fs::read_dir)
  |     +-- FAIL -> silent exit
  |
  +-- Gate 3: KUSER_SHARED_DATA    -- system uptime > 5 minutes
  |     +-- FAIL -> silent exit
  |
  +-- Gate 4: PEB.BeingDebugged    -- inline anti-debug check
  |     +-- FAIL -> silent exit
  |
  +-- Gate 5: sandbox_check()      -- CPU/RAM/disk/uptime hardware metrics
  |     +-- FAIL -> silent exit
  |
  +-- Payload execution:
        XOR decrypt -> VirtualAlloc(RW) -> copy -> VirtualProtect(RX) -> CreateThread
```

Each gate defeats a different analysis approach. Together they ensure the payload only runs on real systems with real users.

---

## Technical Details

| Property | Value |
|----------|-------|
| Language | Rust (self-contained, no shared library) |
| Hash Algorithm | Additive hash (seed `0x1F2E3D4C`, mul `0x1003F`) |
| PEB List | InLoadOrderModuleList |
| Encryption | XOR with 16-byte repeating key |
| Shellcode | 302-byte MessageBox("GoodBoy","OK") + ExitThread |
| Memory | W^X discipline (PAGE_READWRITE -> PAGE_EXECUTE_READ) |
| Binary Size | 278 KB |
| VT Score | 0/76 achieved (March 12, 2026) |

---

## Dual Hashing Architecture

This binary uses **two independent hash algorithms**:

```
LAYER 1: The Rust Loader
  Algorithm: Additive hash (seed 0x1F2E3D4C, wrapping_mul 0x1003F, xor h>>11)
  Purpose:   Resolves VirtualAlloc, VirtualProtect, CreateThread from kernel32.dll
  Location:  Pre-computed constants in .rdata

LAYER 2: The Embedded Shellcode
  Algorithm: ROR13 (Metasploit "block_api" style)
  Purpose:   Resolves LoadLibraryA, MessageBoxA, ExitThread
  Location:  Immediate values in shellcode x86-64 instructions
```

Both must be reversed independently. The Learning Path covers both with Python rainbow table scripts and disassembly walkthroughs.

---

## Course Progression

This is **Stage 01** of 15. Each stage adds one new offensive technique on top of the previous:

```
  EASY              MEDIUM            HARD              INSANE
  ............      ............      ............      ............
  Stage 01 (this)   Stage 04          Stage 07          Stage 14
  Stage 02          Stage 05          Stage 08          Stage 15
  Stage 03          Stage 06          Stage 09
                    Stage 11          Stage 10
                                      Stage 12
                                      Stage 13
```

| Stage | Technique | What's New |
|-------|-----------|------------|
| **01** | **Basic Loader** | **XOR decrypt, PEB-walk, VirtualAlloc->VirtualProtect->CreateThread** |
| 02 | XOR Cryptanalysis | Known-plaintext attack, IC key-length detection |
| 03 | AES + Jigsaw | Entropy normalization, payload fragmentation |
| 04 | API Hashing | Deep dive into PEB internals, rainbow tables |
| 05 | APC Injection | Early Bird, cross-process execution, remote-side decryption |
| 06 | Variant Analysis | Same technique, different keys — family clustering |
| 07 | "Direct Syscalls" | The name is a lie — and that's the lesson |
| 08 | Indirect Syscalls | Call stack forensics, gadget scanning, SSN resolution |
| 09 | Anti-Debug | 7 techniques: PEB, NtQueryInfo, RDTSC, hardware breakpoints |
| 10 | Anti-Sandbox | Hardware fingerprinting, weighted scoring, VM evasion |
| 11 | Persistence | Registry Run key, scheduled tasks, COM hijacking |
| 12 | Module Stomping | Overwrite legitimate DLL .text section, CFG-valid execution |
| 13 | Sleep Obfuscation | Encrypt payload during sleep, 95% scanner miss rate |
| 14 | Combined Loader | 8-layer evasion stack, MBA obfuscation, multi-phase chain |
| 15 | C2 Agent | Full command-and-control with encrypted HTTPS beaconing |

---

## The Learning Path Includes

### Theory (Section 1)
- Why loaders exist (DEP bypass)
- The shellcode staging pipeline (visual diagram)
- W^X vs RWX memory discipline
- Why API hashing eliminates static import analysis
- Dual hashing architecture (additive hash + ROR13)

### Static Analysis Exercises (Section 2)
- Import table analysis — what the IAT reveals and hides
- Encrypted payload identification — entropy scanning in Ghidra
- Hash algorithm recognition — finding the additive hash in disassembly
- Python rainbow table script — map all hash constants to API names
- XOR cipher identification — distinguishing XOR from RC4/AES

### Dynamic Analysis Exercises (Section 3)
- 5-gate startup sequence observation
- Memory allocation breakpoint (`bp NtAllocateVirtualMemory`)
- Shellcode copy observation (hardware write breakpoint)
- RW->RX critical transition (`bp NtProtectVirtualMemory`)
- Shellcode execution tracing (step through MessageBox call)

### Detection Engineering (Section 4)
- YARA rule targeting additive hash seed + multiplier
- Sigma rule for RW->RX memory permission transitions
- ETW-based detection (EtwTi provider)
- Detection gap analysis — what Sysmon can't see

### Evasion Engineering (Section 4B)
- Complete VT forensic timeline (8 submissions, 0/76 -> 1/76)
- Sample burning case study — how VT submissions train AV against you
- 5 empirical evasion principles with proof
- Why evasion code can BE the detection signature

### Adversarial Thinking (Section 5B)
- Break your own YARA rule (3 approaches)
- Break your own Sigma rule (4 approaches)
- Make the binary invisible to pe-sieve (3 approaches)

### Knowledge Check (Section 6)
- 7 questions with expandable answers covering all major concepts

---

## Safety

> **EDUCATIONAL USE ONLY**

- This binary is a proof-of-concept for authorized security training, research, and CTF competitions
- **Payload**: `MessageBox("GoodBoy")` — pops a harmless dialog box, then exits
- No network activity, no file writes (except %TEMP% breadcrumbs), no persistence, no system modifications
- **WRITE** code on your host machine. **EXECUTE** only in isolated VMs
- See `SAFETY.md` for complete lab safety guidelines

**Do NOT submit this binary to VirusTotal** — doing so trains AV engines against it (see "sample burning" in the Learning Path).

---

## Requirements

| Tool | Purpose | Link |
|------|---------|------|
| Windows 10/11 x64 VM | Execution environment | [FlareVM](https://github.com/mandiant/flare-vm) recommended |
| Ghidra 11.x | Static analysis / disassembly | [ghidra-sre.org](https://ghidra-sre.org/) |
| x64dbg | Dynamic analysis / debugging | [x64dbg.com](https://x64dbg.com/) |
| ScyllaHide | Anti-anti-debug plugin for x64dbg | [GitHub](https://github.com/x64dbg/ScyllaHide) |
| Python 3.10+ | Rainbow table scripts, decryption exercises | [python.org](https://python.org/) |
| PE-bear | PE structure viewer | [GitHub](https://github.com/hasherezade/pe-bear) |

**Recommended VM Configuration** (for Gate 5 — sandbox detection to pass):
- 4+ CPU cores
- 8+ GB RAM
- 100+ GB disk
- Let the VM run for 5+ minutes before executing the binary
- Screen resolution 1920x1080 or higher

---

## About the Goodboy Framework

A comprehensive malware development & analysis course with:
- **15 progressive stages** from basic loader to full C2 agent
- **16,500+ lines** of educational documentation
- **Dual perspective** — every technique taught from both offense and defense
- **Empirical AV/ML evasion data** from testing against 76+ antivirus engines
- **Production-grade Rust code** — not toy demos
- **CTF challenges** for each stage (competitive format)
- **AV/ML Bypass Field Guide** with per-engine bypass reference

All 15 binaries achieved 0/76 on VirusTotal. The course documents not just HOW to achieve this, but also what happens AFTER — the sample burning phenomenon, the ML arms race, and why the act of testing IS the burn.

---

## License

This material is provided for educational purposes in authorized security training, research, penetration testing, and CTF competitions. Not for unauthorized access or operational deployment against systems without explicit written permission.

## Author

Built with Rust 1.93.1 MSVC | Tested against 76+ AV engines | March 2026
