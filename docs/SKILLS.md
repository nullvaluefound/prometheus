# Model skills

The Forge chat, investigation leads and review runs load procedure on demand, as ARTEX does. Each skill is a git-reviewed `SKILL.md` under `.agents/skills/`. A session's prompt lists the name and description of every skill its role may see, and `load_skill` returns one body (`re_harness/skills.py`). A role can also have skills **pinned**: their bodies are already in the prompt, for models that may never call `load_skill`.

Skills advise; code enforces. Every rule that must hold is in the broker, the investigation store or the reference check, never only in a skill.

## The model-facing skills

| skill | for | roles |
|---|---|---|
| `static-triage` | the workflow for one question: which tool in which order, and record before answering | intake, native, evidence |
| `recording-evidence` | facts and findings: exact fields, the reference check, sources, negative results | all |
| `pe-triage` | PE header fields, section flags, entropy, entry point, overlay, packing | intake, native, evidence |
| `elf-triage` | ELF header fields, libraries and symbols, static, stripped, Go, Rust and IoT builds | intake, native, evidence |
| `import-analysis` | imports, API families to capabilities and ATT&CK, the caveats that change the reading | native, evidence, review |
| `string-triage` | string locations, which page to ask for, classifying recovered strings safely | intake, native, evidence |
| `capa-yara` | reading capa and YARA results, warnings, corroboration | all |
| `function-analysis` | choosing a function, cross-references, decompilation patterns and constants | native |

`static-malware-re`, `static-re-native` and `static-re-evidence` describe the operator workflow for external MCP clients and stay visible to the roles that had them.

## How they are written

They follow ARTEX's skill shape: a description that says when to load the skill, then procedure, decision tables and a completion check. They are written for a small model (the baseline is a 9B Qwen-family model):

- At most about ten rules. The most important come first and are repeated at the end; small models follow early instructions best and lose the middle of long contexts.
- Exact JSON call templates with the argument names the tools accept.
- Decision tables in the form IF a result shows X THEN record Y, with the strength of each signal.
- One compact worked example per record type, not many.
- No long reference dumps: each skill stays under about 6 KiB.
- The harness does arithmetic for the model. `artifact_summary` carries a `derived` block (the entry point's virtual address and section for PE, the entry in hex for ELF) because the model converted addresses wrongly in measurement.

A test (`tests/test_measurement.py`) refuses a skill that names a tool the models do not have.

## Facts, as in ARTEX

ARTEX registers facts with `record_fact`: a confidence (`observed` or `inferred`) and a source, where content the target itself returned (`target_response`) never proves a goal. Prometheus keeps the same method and makes more of it code:

- `record_observation` is the fact. `observed` needs evidence ids, which name exact tool results by hash, and every address and SHA-256 in its text must appear in that evidence.
- The Forge sets the source from the cited evidence: `sample_content` (string text, import names, YARA-matched bytes: what the sample's author controls), `tool_output` (header, capa, Ghidra), or `inference`.
- `propose_finding` may cite observations, so a finding rests on facts and facts on evidence.
- `propose_answer` refuses an answer that rests only on `sample_content`.
- Skills teach one consolidated fact per tool result, and recording negative results.

## Measuring a skill change

Benchmarks adopt. Change a skill or `skills.PINNED` only on a benchmark comparison (`python -m tests.benchmark.run`, several runs per setup: one run says little, because a small model varies between runs). Record the setup, model, recall and precision. Precision there means "matched a known property of the fixture": a true claim the benchmark does not list also lowers it.

The comparison behind this skill set (`artex-9b-64k` on Ollama, four runs per setup, two operator follow-ups, record nudge on):

| setup | recall per run | mean recall | mean precision | mean seconds |
|---|---|---|---|---|
| listed: these skills, loaded on demand | 1.0, 0.6, 1.0, 1.0 | 0.90 | 0.90 | 150 |
| pinned: `static-triage` and `recording-evidence` in the prompt | 0.8, 1.0, 1.0, 0.6 | 0.85 | 0.71 | 138 |
| old: only the three operator-workflow skills | 1.0, 1.0, 0.6, 1.0 | 0.90 | 0.88 | 106 |

What it shows:

- Pinning lowered precision, because the model proposed more claims, so `PINNED` stays empty. Listed sessions loaded `static-triage` themselves in every run.
- The old and new skills tie on this benchmark. Before the harness aids (derived fields, the record nudge, failing references and the duplicate guard), the same model averaged recall between 0.4 and 0.8 depending on the setup. The gain came from those aids, not the skill text.
- The benchmark's five properties are header facts (format, entry point, one import, the ELF libc). They do not exercise what the new skills add (import families, strings, capa, functions and packing signals). A benchmark with such properties is what would show whether that content helps.

## Sources

The technique content was researched for this skill set. Main references:

- PE: the Microsoft PE/COFF specification; Lyda and Hamrock's entropy study (IEEE S&P 2007); pefile's `peutils`; Mantovani et al., NDSS 2020, on low-entropy packing; Hexacorn's PE section name list; *Practical Malware Analysis* (Sikorski and Honig), chapters 1 and 18.
- ELF: `elf(5)`; Go's `debug/gosym` and `debug/buildinfo`; JPCERT and Microsoft on Rust malware; Unit 42, Trend Micro and Forescout on Mirai variants.
- Capabilities: MITRE ATT&CK (including the v19 changes of April 2026) and the Malware Behavior Catalog; Elastic's process injection survey; Check Point's anti-debug and evasions encyclopedias; CISA's ATT&CK mapping guidance.
- capa and YARA: the capa rules repository and format documentation; the Neo23x0 YARA style guide.
- Strings: Mandiant's StringSifter and PDB path research; Check Point on prompt injection aimed at AI malware analysis (2025).
- Small models and tools: OpenAI's function calling and GPT-4.1 prompting guides; Anthropic's guides on effective agents and writing tools; Qwen's function calling documentation; BFCL v3 and v4; "Lost in the Middle" (arXiv 2307.03172); Chroma's context-rot study; τ-bench; MAST (arXiv 2503.13657).
