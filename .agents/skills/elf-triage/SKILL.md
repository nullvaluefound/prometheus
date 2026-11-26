---
name: elf-triage
description: How to read artifact_summary for a Linux ELF file (format_hint "ELF") - class, machine, type, entry and header counts - find its libraries and symbols with artifact_imports, and recognize static, stripped, Go, Rust and IoT-bot builds.
---

# ELF triage

**Rules first:** copy every number exactly; symbols show what code can call, not what it does; statically linked files hide most of this.

## 1. Header (`summary.elf`)

| field | values |
|---|---|
| `elf_class` | 1 = 32-bit, 2 = 64-bit |
| `data_encoding` | 1 = little-endian, 2 = big-endian |
| `e_type` | 2 = executable at a fixed address; 3 = shared object or position-independent executable |
| `machine` | 3 = x86, 62 = x86-64, 40 = ARM, 183 = AArch64, 8 = MIPS, 20 = PowerPC, 42 = SuperH |
| `e_entry` | entry address as an integer. Do not convert it yourself: copy `derived.e_entry_hex` (4160 → `0x1040`) |
| `phnum`, `shnum` | program and section header counts |

## 2. Libraries and symbols

Call `artifact_imports` with `{"artifact": "<sha256>", "offset": 0, "limit": 50}`. It needs a grant; if refused, add a reason with `note_grant_need` and continue. With a grant, row kinds are `elf_needed` (a required library, such as `libc.so.6`), `elf_import` (a function it calls) and `elf_export` (a symbol it defines). If `has_more`, call again with `offset` 50.

## 3. Signals

| IF you see | THEN record | strength |
|---|---|---|
| `shnum` 0 | "section headers removed" (packers, deliberate stripping) | medium |
| no `elf_needed` rows | "statically linked: libraries are inside the file; capa and Ghidra hits may be in library code" | medium |
| machine 40, 8, 20 or 42 | "built for routers or IoT devices" (common for Mirai-like bots, often UPX-packed, static and stripped) | weak alone |
| a large static file with thousands of functions | "possibly a Go or Rust build" (confirm with strings: `Go buildinf:`, `panicked at`, `/rustc/`) | weak |
| strings `UPX!` | "packed with UPX" | strong (needs a string grant) |
| strings `--donate-level`, `--randomx`, `stratum+tcp` | "cryptocurrency miner configuration" (T1496.001) | medium |

## 4. What symbols suggest (kind `inferred`)

| symbols | capability | ATT&CK |
|---|---|---|
| `socket`, `connect`, `send`, `recv`, `getaddrinfo` | network communication | T1095 / T1071 |
| `fork` + `setsid` + `chdir` | runs as a background daemon | inferred |
| `execve`, `system`, `popen` | runs commands | T1059.004 |
| `ptrace` | anti-debugging (on itself) or injection (on others) | T1622 / T1055.008 |
| `memfd_create` + `execve` | runs code from memory without a file | T1620 |
| `dlopen`, `dlsym` | loads code at run time | T1129 |
| `prctl` (set name), overwriting `argv` | disguises its process name | T1036 |
| `unlink` of its own path | deletes itself | T1070.004 |
| `opendir` of `/proc` + `kill` | finds and kills other processes (bot rival-killers) | T1057 |

Strings such as `crontab`, `.service`, `/etc/rc.local`, `authorized_keys` and `/etc/ld.so.preload` point to persistence (T1053.003, T1543.002, T1098.004, T1574.006).

## What to record

One `observed` observation for the header (cite `artifact_summary`) and one for the library list (cite `artifact_imports`), naming each library exactly. Capabilities go in an `inferred` observation that names the symbols.

**Rules again:** copy numbers exactly; symbols are capability, not behavior; say what static linking or stripping hid.
