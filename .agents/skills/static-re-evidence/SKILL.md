---
name: static-re-evidence
description: Preserve derived-artifact lineage, check findings, and prepare verified evidence handoff for a static malware case.
---

# Evidence and findings

Use the [evidence role](../../../agents/evidence/AGENTS.md) to draft findings and the [review role](../../../agents/review/AGENTS.md) to test conclusions. Cite original and derived SHA-256 values, exact offsets or addresses, methods and provenance. Record complete versus partial inputs and avoid treating format hints, signatures or a successful parser as proof of behavior.

Ask the operator to save raw provider evidence locally when the bounded model excerpt is insufficient. Identify which call paths and artifacts were actually inspected and which branches remain unknown. Replace a disputed finding with a new one that supersedes its ID, since the ledger is append-only. Prepare an assessment, verified ledger and justified indicators before the operator closes the case. Closure is irreversible and leaves the case read-only. The [operator runbook](../../../docs/OPERATIONS.md) covers derivation and export.
