# Tool inventory

| Dependency | Required for | Packaging |
| --- | --- | --- |
| Python 3.10+ | Host CLI, stdio MCP, policy, audit and local Ollama protocol | Operator machine |
| Docker Engine with Buildx | Build and run amd64 Linux workers | Windows bootstrap supports Docker Desktop and Ubuntu WSL 2 |
| Ubuntu 24.04 base | Worker userspace and distribution dependencies | Base image pinned by registry digest |
| OpenJDK 21 | Ghidra, PyGhidra and REA Ghidra provider | Ubuntu packages in image |
| Ghidra 12.1.4 | Native loading, analysis and decompilation | Official release asset checked by SHA-256 |
| LaurieWired GhidraMCP 2.0 | Headless static MCP functions, xrefs and decompilation | Release ZIP checked by SHA-256, then wheel and extension extracted |
| PyGhidra and Python MCP SDK | Headless Java bridge and local stdio sessions | Hash-locked Python environment |
| Node 24.22.1 and REA 6.8.0 | `inspect` and `decompile` using REA's Ghidra 12.1 provider | Node base pinned by digest, REA locked with npm integrity fields |
| yara-python 4.5.4 | Offline YARA scans with operator-imported rules | Hash-locked Python environment |
| capa 10.0.0, capa-rules 10.0.0 and FLIRT signatures | Capability triage of PE and ELF with the vivisect backend | Package hash-locked. Rules archive and source signatures checked by SHA-256, with a prebuilt rule cache |
| pefile, file, binutils and jq | PE triage, granted `artifact_imports` names and operator diagnostic utilities | Python and Ubuntu image packages |
| tini | Process-group signal handling inside workers | Ubuntu package in image |
| Ollama or a stdio MCP client | Optional model-driven analysis | Operator selects the client and model |

Upstream references for the pinned providers. [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build), [GhidraMCP 2.0](https://github.com/LaurieWired/GhidraMCP/releases/tag/2.0), [REA 6.8.0](https://github.com/morluto/rea/releases/tag/rea-agents-6.8.0), [capa 10.0.0](https://github.com/mandiant/capa/releases/tag/v10.0.0), [capa-rules 10.0.0](https://github.com/mandiant/capa-rules/releases/tag/v10.0.0), [yara-python 4.5.4](https://pypi.org/project/yara-python/4.5.4/).

## Exposed tools

Every successful sample-tool reply also carries `evidence_id`: the SHA-256 under which the broker stored exactly that reply in the case's evidence folder (docs/SAFETY.md). Cite it in observations, proposed findings and `finding --evidence evidence:<sha256>`.

| Name | Accepted selectors beyond SHA-256 | Basic result |
| --- | --- | --- |
| `artifact_summary` | None | Format hint (`PE candidate`, `ELF`, `Mach-O`, `Mach-O universal`, `ZIP candidate`, `script` or `unknown`), length, string count and numeric header fields. PE adds machine, image base, entry RVA, overlay offset, section, import-library and certificate counts, and up to 96 sections as RVA, raw offset, raw size, virtual size, flags and entropy. ELF adds class, encoding, machine, type, entry, and program and section header counts. Thin Mach-O adds CPU type and file type. Section, import, version and string names are never included |
| `artifact_imports` | Offset, limit | Requires a grant. Rows of PE section names with RVA, import and delay-import DLL names, and function names or ordinals with IAT slot RVA. ELF gives `DT_NEEDED` libraries and named `.dynsym` imports and exports with value. Each row carries `kind`, `index`, `library` index, `name`, `name_hex`, `name_bytes`, `ordinal` and `address`. Limitations name a missing parser, parse failure or cap |
| `artifact_strings` | Offset, limit | File offsets and byte lengths of ASCII and UTF-16LE strings |
| `ghidra_functions` | Offset, limit | Function entry addresses |
| `ghidra_xrefs` | Address, offset, limit | Static inbound cross-reference addresses |
| `ghidra_decompile` | Address | Granted excerpt of a native function |
| `rea_inspect` | None | Bounded provider status, with details available by grant or local capture |
| `rea_decompile` | Address | Granted excerpt using the REA Ghidra frontend |
| `yara_scan` | Offset, limit | Matched rule names, tags, string identifiers, and file offsets and lengths of up to 8 hits per string. Matched bytes (64 max per hit) and rule metadata require a grant |
| `capa_triage` | Offset, limit | Capability names and namespaces, ATT&CK and MBC IDs, match counts, up to 8 function addresses, capa format, arch and OS, and any packer or installer limitation. Up to 64 addresses, rule descriptions and analysis layout by grant |

Native admission covers common ELF, PE with its signature in the first 4 KiB, and thin Mach-O signatures. Format and loader support can narrow this further. For a long or unusual sample, record any parser limit and use separate approved tools in an isolated lab. The built-in REA lane selects only its Ghidra native provider. It does not offer runtime, browser, ADB, script, emulator, remote provider or install operations. Both frontends share Ghidra analysis, so matching results should be attributed accordingly.

### Import names

Section, import and symbol names are sample text, so `artifact_imports` returns nothing without an operator grant for the exact artifact, offset, limit and audience. The worker keeps up to 96 sections, 256 import and delay-import DLLs, 512 functions per DLL and 8,192 rows in all, and reads each name to 256 bytes. Bytes outside printable ASCII become `?`. When that changes or cuts a name, `name_hex` holds the first 256 original bytes and `name_bytes` the full length. The host projection accepts only listed kinds, printable names consistent with their hex, bounded integers, hex addresses and a fixed set of limitations. The ELF reader parses section headers with the standard library and stops on any out-of-range read. Without pefile, a PE yields only the `pefile_unavailable` limitation.

### Scanner controls

Rule text names the results of both scanners, so the summaries show rule names without a grant. Sample bytes stay behind a grant. capa uses only the rule set pinned in the image. YARA uses the one rule file the operator imports into each case with `yara-rules`. The worker compiles it with includes disabled and keeps only the `pe`, `elf`, `math`, `hash`, `dotnet`, `string` and `time` modules. Other imports, including `console`, are refused at import and again at every scan. The broker sends the SHA-256 recorded in `scope.json`, and the worker refuses rules that don't match it. The broker also withholds the result if the rules change during a scan. Importing new rules retires every `yara_scan` grant, because those grants released bytes matched under the old rules. The host projection accepts only YARA identifiers, printable capa names, canonical ATT&CK and MBC IDs, and hex addresses. capa analyzes only PE and ELF headers that pass the native admission check, with a 240-second provider budget and a 300-second worker budget.

capa runs its own vivisect disassembly, so its addresses can differ from Ghidra's function boundaries. Confirm a capability at its address with `ghidra_xrefs` or a granted decompilation before you cite it as observed. A listed limitation, such as a packer or installer, means capa saw little of the real code.

For cases that require it, an analyst can stage further independently trusted static parsers in a separate reviewed tool image. Typical additions include format-specific archive tools and a signature verifier with an explicit offline revocation policy. Tools that expand the parse or disclosure surface require their own input and output controls before any model integration.

## Case-state tools

These tools read and write the case's investigation store through the broker, with no worker run. Roles get them through the same allowlist as sample tools: `intake` can read and write notes, `native` and `evidence` can also propose findings, and `review` can only read.

| Name | Arguments | Result |
| --- | --- | --- |
| `case_overview` | `offset`, `limit` | Open questions, the plan, a page of leads with observation counts, and recent proposals with their check result. Model-written text whose grants are not active for the reader is withheld |
| `lead_detail` | `lead` | One lead and its latest 50 observations |
| `add_lead` | `artifact`, `title`, optional `address`, `offset`, `question` | A lead anchored to an admitted SHA-256 |
| `record_observation` | `kind` (`observed` or `inferred`), `text`, `artifact`, optional `lead`, `evidence` | An observation. `observed` needs at least one evidence id from this case |
| `update_plan` | `items` (up to 20) | Replaces the plan |
| `propose_finding` | `claim`, `kind`, `confidence`, `artifacts`, `evidence`, optional `limitations`, `counterevidence`, `question`, `lead` | A candidate with its reference check result. Only the operator records findings |
