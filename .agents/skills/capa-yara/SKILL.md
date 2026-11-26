---
name: capa-yara
description: Read capa_triage capability matches (rule, namespace, ATT&CK, MBC, function addresses) and yara_scan rule matches, tell warnings from capabilities, and corroborate a match before claiming behavior.
---

# capa and YARA results

**Rules first:** a match is a lead, not a verdict; read capa's `limitations` and `internal/limitation/` rows before anything else; corroboration needs a different kind of evidence, not another pattern over the same bytes.

## capa_triage

Call `{"artifact": "<sha256>", "offset": 0, "limit": 50}`; if `has_more`, page with `offset` 50, 100 ….

Top-level: `capabilities` (total), `format`, `arch`, `os`, `limitations`, `rules_withheld`. Each row: `rule`, `namespace`, `attack` (ATT&CK ids), `mbc` (Malware Behavior Catalog ids), `matches`, `addresses` (up to 8 function addresses).

| namespace starts with | means | check before relying on it |
|---|---|---|
| `internal/limitation/` | **a warning, not a capability**: packed, installer, AutoIt, VB or .NET single-file results may be incomplete | treat every other match as partial |
| `anti-analysis/` (anti-debugging, anti-vm, obfuscation, packer) | evasion | reachable? the C runtime triggers some anti-debug rules |
| `host-interaction/` | processes, files, registry, services | which key, process or file |
| `communication/` | sockets, HTTP, DNS | strings or URL building near the call |
| `data-manipulation/` (encryption, encoding, hashing) | crypto and encoding | constants and loop shape; what the data is |
| `load-code/` | loading or resolving code at run time | what is loaded |
| `persistence/` | run keys, services, tasks | a concrete location string |
| `collection/`, `impact/` | capture, damage | several corroborating strands |
| `executable/`, `compiler/`, `runtime/`, `linking/` | file facts (packer, .NET, Go, static libraries) | context for the other hits |
| `malware-family/` | a named family | strong but one claim |
| `nursery/` | less mature rules | lower weight |

**Scope:** a row with `addresses` matched inside functions; decompile them. A file-scope row (no addresses) gives no location.

**Corroboration recipe:**

1. `ghidra_decompile` a match address (needs a grant).
2. Confirm the API call or constant is there.
3. `ghidra_xrefs` on it: zero callers, and not an entry point or export, means it may be dead code; say so.
4. Cross-check with imports or strings.
5. Only then use kind `corroborated`.

capa, Ghidra and REA share Ghidra's disassembly, so their agreement does not rule out a disassembly error. capa's file-scope rules read the same headers as `artifact_summary` and `artifact_imports`.

**False positives:** C runtime code, statically linked libraries (Go, Rust, libc), and packer stubs. Packed samples show the stub's capabilities, not the payload's. No matches is weak evidence of no capability.

## yara_scan

Rules come from the operator; IF refused with `yara_rules_not_imported` THEN skip YARA.

Each row: `rule`, `namespace`, `tags`, `strings` (identifier, instance count, match offsets and lengths). Matched bytes need a grant; offsets do not.

- The rule name is its author's claim. Common prefixes: `MAL_`, `APT_`, `HKTL_` (specific malware or tools), `SUSP_` (heuristics), `PUA_` (unwanted software).
- Map match offsets to sections: a hit in the overlay, resources or a high-entropy region means "contains these bytes", not "runs them".
- A YARA rule over strings, imports or section names does **not** corroborate those same fields: it re-reads the same bytes.
- A family name needs two independent strands, for example a family YARA rule plus matching code in decompilation. Even then, kind `inferred`.

## What to record

- Observed: "capa matched `<rule>` (namespace `<namespace>`, ATT&CK `<id>`) at 0x401230", citing the `capa_triage` evidence id, copying the address from `addresses`. Record warnings from `limitations` too.
- Inferred: what the capability means for the question.
- In `limitations`: "capa matches code patterns; reachability and triggering conditions were not established."

**Rules again:** matches are leads; read the limitations first; corroborate with a different kind of evidence.
