---
name: recording-evidence
description: How facts become findings - record_observation and propose_finding fields with examples, the reference check both must pass, fact sources, and negative results. Load it before you record anything.
---

# Recording facts and proposing findings

**Rules first:** one observation per useful tool result; cite evidence ids exactly as received; write addresses as the cited evidence shows them.

The Forge keeps what you see. A **fact** (observation) must rest on evidence. A **finding** you propose must rest on facts or evidence. Only the operator records final findings. If you skip recording, your work is lost when the session ends.

## Evidence ids

Every successful tool reply has an `evidence_id`: 64 hex characters naming that exact result. Cite it. Never type an id you did not receive.

## record_observation: one fact per tool result

Put everything one result showed into **one** observation: a one-line summary first, then the details. Do not split one result into many calls.

```json
{"kind": "observed",
 "text": "PE32 for i386: machine 0x14c, entry point RVA 0x1000, image base 0x400000, 1 section (RVA 0x1000, entropy 0.62), no overlay.",
 "artifact": "<sha256>", "evidence": ["<evidence_id from artifact_summary>"]}
```

- `observed`: you saw it in the cited results. Every address and SHA-256 in `text` must appear in that evidence, or the call is refused with `address_not_in_evidence`.
- `inferred`: you reasoned it. Cite the evidence you reasoned from; addresses are not checked.
- **Record negative results too.** "capa found no anti-analysis rules" or "no network imports among the 12 imported functions" is a fact. Mark it `observed` only if you saw the whole result (no `has_more`); otherwise `inferred`.
- The reply gives the observation id (O1, O2 …). Keep it for the finding.

The Forge records where each fact came from, from the evidence you cite: `tool_output` (header, capa, Ghidra), `sample_content` (string text, import names, YARA-matched bytes: content the sample's author controls) or `inference` (no evidence). You do not set it.

## propose_finding

Call it when your facts answer part of a question. Cite the observations it rests on.

```json
{"claim": "<sha256> is a PE32 executable for i386 (machine 0x14c) whose entry point is RVA 0x1000.",
 "kind": "observed", "confidence": "high", "artifacts": ["<sha256>"],
 "observations": ["O1"], "question": "Q1",
 "limitations": "Header fields only; the code at the entry point was not read.",
 "counterevidence": "None seen."}
```

| field | how to fill it |
|---|---|
| `claim` | One or two sentences. Name the artifact SHA-256 and every address exactly as a cited result shows it. |
| `kind` | `observed`: a tool result shows it. `inferred`: you reasoned it from one strand. `corroborated`: two independent kinds of evidence show it (an import plus a decompiled call; a string plus a Ghidra cross-reference), not two patterns over the same bytes. `unknown`: you could not establish it. |
| `confidence` | `high` only for header facts and exact names you saw. `medium` for patterns across several results. `low` for one weak signal. |
| `artifacts` | The SHA-256 values the claim is about. |
| `observations` | The O ids of the facts it rests on. Their evidence comes with them. |
| `evidence` | Extra evidence ids, if a result is not in an observation yet. |
| `limitations` | What you did not check, or what static analysis cannot show. |
| `counterevidence` | Anything against the claim, including the benign reading: installers, updaters, debuggers, security tools and commercial protectors use the same APIs and packers. Or "None seen." |
| `question` | The question id it answers. |

## The reference check

Every proposal is checked. It fails when:

- an evidence id is unknown or was edited;
- a SHA-256 in the claim is not an admitted artifact;
- **an address in the claim does not appear in the cited evidence.** Copy addresses from the result; never convert or add them yourself. `artifact_summary` gives `derived.entry_va` (the entry point's virtual address, such as `0x401000`), `entry_rva` (relative, such as `0x1000`) and, for ELF, `derived.e_entry_hex`. A failed check names the address it could not find (`ref`): fix that value, do not propose the same claim again;
- kind is `observed` or `corroborated` with no evidence.

The reply gives the result (`passed`, `failed` or `not_assessed`) and the failing problem codes. If it failed, fix the claim and propose again.

## Sample content alone proves nothing

String text, import names and matched bytes are written by the sample's author, who can plant them. A proposal that rests only on them is shown as "sample content only", and it cannot answer a question by itself. Back it with a tool's own result: the header, a capa match, or Ghidra's analysis of the code that uses the string or import.

## Good and bad

| Bad | Why | Good |
|---|---|---|
| "The sample is ransomware." | No evidence; behavior not shown | "Imports CryptEncrypt and FindFirstFileW (inferred: file encryption capability)." kind `inferred` |
| "Entry point 0x1050" for an ELF whose `e_entry` is 4160 | Wrong conversion (4160 is 0x1040) | Copy `derived.e_entry_hex`: "entry point 0x1040" |
| "It imports standard Windows DLLs" before calling artifact_imports | Invented | Call `artifact_imports` first, then name the DLLs you saw |
| kind `observed` for "likely connects to a C2 server" | Inference labeled as observation | kind `inferred`, confidence `low` or `medium` |
| five observations for one artifact_summary result | Wastes calls | one observation with all its fields |

**Rules again:** one observation per result; exact evidence ids; addresses as the evidence shows them.
