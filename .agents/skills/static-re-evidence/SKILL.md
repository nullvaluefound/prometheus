---
name: static-re-evidence
description: Preserve derived-artifact lineage, check findings, and prepare verified evidence handoff for a static malware case.
---

# Evidence and findings

Use the [evidence role](../../../agents/evidence/AGENTS.md) to draft findings and the [review role](../../../agents/review/AGENTS.md) to test conclusions. Cite original and derived SHA-256 values, exact offsets or addresses, methods and provenance. Record complete versus partial inputs and avoid treating format hints, signatures or a successful parser as proof of behavior.

Ask the operator to save raw provider evidence locally when the bounded model excerpt is insufficient. Identify which call paths and artifacts were actually inspected and which branches remain unknown. Close with an assessment, verified ledger and justified indicators. The [operator runbook](../../../docs/OPERATIONS.md) covers derivation and export.
