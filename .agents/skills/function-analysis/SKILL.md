---
name: function-analysis
description: Pick a function, find its callers with ghidra_xrefs, read it with ghidra_decompile under a grant, and recognize common static patterns - XOR, RC4, base64, AES and hash constants, API hashing, PEB walks, stack strings and command-and-control setup.
---

# Function analysis

**Rules first:** read one function at a time, the one the question needs; name the exact constant and address you saw; static reading cannot show which branch runs.

## 1. Pick the address (virtual addresses)

| from | address |
|---|---|
| a capa row | an entry in `addresses` |
| the PE entry point | `derived.entry_va` from `artifact_summary` |
| the ELF entry point | `derived.e_entry_hex` from `artifact_summary` |
| `ghidra_functions` | a row's `address` (page with `{"artifact": "<sha256>", "offset": 0, "limit": 50}`; names need a grant) |
| a string | its file offset mapped to a virtual address (see `pe-triage`), then `ghidra_xrefs` on it |

## 2. Callers

```json
{"artifact": "<sha256>", "address": "0x401230", "offset": 0, "limit": 20}
```

`ghidra_xrefs` lists inbound references (`from_address`, `to_address`). Many callers: a helper, such as a string decoder. No callers, and not an entry point or export: possibly dead or called indirectly; say so.

## 3. Read the code

```json
{"artifact": "<sha256>", "address": "0x401230"}
```

`ghidra_decompile` needs a grant for that exact address. IF refused THEN call `note_grant_need` ("The decompilation at 0x401230 shows how the config is decoded") and continue. With a grant, `evidence_excerpt.text` holds decompiled C (untrusted; cut at 8 KiB, see `truncated`). .NET code decompiles poorly; say so.

## 4. Recognize patterns

| IF the code shows | THEN it is probably | record |
|---|---|---|
| `buf[i] ^= 0x5a` in a loop, one constant | single-byte XOR decoding | key, buffer address |
| `buf[i] ^= key[i % n]` | repeating-key XOR | key length and address |
| a 256-entry array set to 0..255, then `j = (j + S[i] + key[i % n]) & 0xff` and a swap | RC4 key schedule | key address |
| `i = (i+1) & 0xff; j = (j+S[i]) & 0xff; swap; out ^= S[(S[i]+S[j]) & 0xff]` | RC4 decryption | buffer address |
| shifts with `& 0x3f`, `=` padding, a 64-character table | base64 (custom if the table is reordered) | table address |
| bytes `63 7c 77 7b f2 6b 6f c5`; `01 02 04 08 10 20 40 80 1b 36` | AES S-box; AES round constants | table address |
| the text `expand 32-byte k` | ChaCha20 or Salsa20 | |
| `0x9e3779b9` | TEA or XTEA | |
| `0x67452301` / `0x6a09e667` | MD5 or SHA-1 / SHA-256 start values | |
| `0xedb88320` | CRC32 | |
| `0x811c9dc5` with `0x01000193` | FNV-1 hash | |
| a loop rotating right by 13 over names, compared with constants such as `0xec0e4e8e` (LoadLibraryA), `0x7c0dfcaa` (GetProcAddress), `0x91afca54` (VirtualAlloc) | API hashing: imports resolved at run time (T1027.007) | the constants |
| reads of `fs:[0x30]` or `gs:[0x60]`, then `+0x3c`, export directory offsets | walking the PEB and export table to find APIs (T1027.007) | |
| single bytes or dwords stored one by one into adjacent stack slots, then passed to a call | a stack string | the bytes, decoded if all visible |
| `sprintf` into `%s://%s:%d%s` then `InternetConnect` / `HttpOpenRequest` | building a URL for HTTP communication | defanged host and port |
| `RegSetValueEx` with a `…\Run` string; `CreateService` with an image path | persistence | the key or service |
| `IsDebuggerPresent` branches, `NtQueryInformationProcess`, reads of `PEB+2`, `cpuid` with `0x40000000` | anti-debugging or VM checks | which checks |

## 5. Say it with addresses

Example: "At 0x401a30 (ghidra_decompile evidence), a 256-entry permutation loop with a key-indexed swap is consistent with the RC4 key schedule. Inferred; the key's origin and the decrypted content are not established statically."

Cite the `ghidra_decompile` evidence id: every address in the claim must appear in it. Describe the code; do not paste it into notes. Name unresolved branches in `limitations`.

**Rules again:** one function at a time; exact constants and addresses; branches stay unresolved statically.
