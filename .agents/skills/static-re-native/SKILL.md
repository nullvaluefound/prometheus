---
name: static-re-native
description: Examine admitted native malware artifacts with case-bound Ghidra MCP and REA for defensive static behavior analysis.
---

# Native static analysis

Read the [native role](../../../agents/native/AGENTS.md). Begin with SHA-256 and a format hint, then use `ghidra_functions` to get function addresses and `ghidra_xrefs` to establish a specific trace. Address a decompilation by canonical hex address. Ask the operator for an exact expiring grant only if a sample-derived excerpt is necessary and the active provider is approved for it. `rea_inspect` uses a static Ghidra provider. Record frontend and limitations if results differ. `capa_triage` gives capability leads at function addresses from a separate vivisect analysis. Confirm each lead in Ghidra before treating it as observed behavior.

Trace evidence for configuration, file and process behavior while distinguishing reachable paths and prerequisites. Keep a bounded list of unresolved questions and cite the tool and location for each material conclusion. Use the [tool inventory](../../../docs/TOOLS.md) for current limits and the [model guide](../../../docs/MODELS.md) for excerpt behavior.
