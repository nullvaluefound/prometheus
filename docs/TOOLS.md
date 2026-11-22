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
| pefile, file, binutils and jq | PE triage and operator diagnostic utilities | Python and Ubuntu image packages |
| tini | Process-group signal handling inside workers | Ubuntu package in image |
| Ollama or a stdio MCP client | Optional model-driven analysis | Operator selects the client and model |

Upstream references for the pinned providers. [Ghidra 12.1.4](https://github.com/NationalSecurityAgency/ghidra/releases/tag/Ghidra_12.1.4_build), [GhidraMCP 2.0](https://github.com/LaurieWired/GhidraMCP/releases/tag/2.0), [REA 6.8.0](https://github.com/morluto/rea/releases/tag/rea-agents-6.8.0).

## Exposed tools

| Name | Accepted selectors beyond SHA-256 | Basic result |
| --- | --- | --- |
| `artifact_summary` | None | Format hint, length, string count and selected header fields |
| `artifact_strings` | Offset, limit | File offsets and byte lengths of ASCII and UTF-16LE strings |
| `ghidra_functions` | Offset, limit | Function entry addresses |
| `ghidra_xrefs` | Address, offset, limit | Static inbound cross-reference addresses |
| `ghidra_decompile` | Address | Granted excerpt of a native function |
| `rea_inspect` | None | Bounded provider status, with details available by grant or local capture |
| `rea_decompile` | Address | Granted excerpt using the REA Ghidra frontend |

Native admission covers common ELF, PE with its signature in the first 4 KiB, and thin Mach-O signatures. Format and loader support can narrow this further. For a long or unusual sample, record any parser limit and use separate approved tools in an isolated lab. The built-in REA lane selects only its Ghidra native provider. It does not offer runtime, browser, ADB, script, emulator, remote provider or install operations. Both frontends share Ghidra analysis, so matching results should be attributed accordingly.

For cases that require it, an analyst can stage independently trusted signatures and static parsers in a separate reviewed tool image. Typical additions include YARA for offline rules, capa for capability triage, format-specific archive tools and a signature verifier with an explicit offline revocation policy. Tools that expand the parse or disclosure surface require their own input and output controls before any model integration.
