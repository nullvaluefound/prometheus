---
name: pe-triage
description: How to read artifact_summary for a Windows PE file (format_hint "PE candidate") - machine type, sections, entropy, flags, entry point, overlay, imports count and certificate - and when the signals add up to packing.
---

# PE header triage

**Rules first:** copy every number exactly; one signal is never enough to call a file packed or malicious; headers show structure, not behavior.

`artifact_summary` gives the header under `summary.pe`. Section and import **names** are withheld; you get numbers.

## 1. Parse and machine

- `pe.parsed` `false`: the header is broken or truncated. Record it and stop PE work. A malformed header is itself a signal.
- `pe.machine`: `0x14c` x86, `0x8664` x64, `0x1c0`/`0x1c4` ARM, `0xaa64` ARM64.

## 2. Section flags

`flags` is a hex bitmask: `0x20` code, `0x40` initialized data, `0x80` uninitialized data, `0x20000000` executable, `0x40000000` readable, `0x80000000` writable.

| flags | usual section |
|---|---|
| `0x60000020` | code (`.text`), read + execute |
| `0x40000040` | read-only data (`.rdata`, `.rsrc`) |
| `0xc0000040` | writable data (`.data`) |
| `0xe0000020`, `0xe0000040`, `0xe0000080` | **writable and executable**: common in packers such as UPX |

## 3. Signals

| IF you see | THEN record | strength |
|---|---|---|
| an executable section with entropy ≥ 7.2 | "high entropy, suggests packed or encrypted code" (inferred) | medium |
| entropy 6.7-7.2 | "ambiguous entropy" | weak |
| a section smaller than 256 bytes | ignore its entropy: it cannot be high | none |
| an executable section with `raw_size` 0 and large `virtual_size` | "empty on disk, filled at run time" (inferred unpack target) | strong |
| writable + executable flags | "self-modifying or unpacking code possible" | medium (benign: MSVC debug `.textbss`) |
| entry point outside every section, in a non-executable section, or in the last section | "unusual entry point" | medium |
| `import_libraries_count` 0-2 | "few imports; may resolve APIs at run time" | medium (benign: .NET files import only `mscoree.dll`) |
| `overlay_offset` set | "data appended after the last section" | weak |
| `certificate_bytes` > 0 | "a signature blob is present" | weak: never write "signed" or "trusted" |

**Entry point section:** `derived.entry_section` is the index of the section that holds the entry point (`null`: outside every section). It is absent when the header has more sections than the summary lists; then do not claim which section holds the entry point.

**Packing rule:** write "likely packed" (kind `inferred`) only when **two or more independent** signals hold: raw size 0 on an executable section, entropy ≥ 7.2 on an executable section, an unusual entry point, few imports, or a capa `anti-analysis/packer/` match. A capa UPX match and a UPX section name are **one** signal: both read the section headers. Low entropy does not prove a file is unpacked.

**Overlay:** signed files always have one, because the certificate is appended after the sections. Installers and self-extractors also keep payloads there. Its content is unknown until read.

## 4. Addresses

- Copy addresses; do not compute them. `derived.entry_va` is the entry point's virtual address (`image_base` + `entry_rva`), the form Ghidra uses. `entry_rva` is relative to `image_base`.
- A file offset `o` is in the section where `raw_offset` ≤ `o` < `raw_offset` + `raw_size`. Its RVA is `o` − `raw_offset` + `rva`.
- In a claim, write an address as the cited evidence shows it (see `recording-evidence`).

## What to record

One observation for the whole header, kind `observed`, citing the `artifact_summary` evidence id. For example: "PE32 for x86 (machine 0x14c), entry point VA 0x401000 (RVA 0x1000) in section 0; 3 sections; the section at RVA 0x5000 has entropy 7.91 and flags 0xe0000020 (writable, executable); 2 import libraries; no overlay." Then one `inferred` observation for any conclusion, such as packing, naming the signals.

**Rules again:** copy numbers exactly; two independent signals before "packed"; headers are structure, not behavior.
