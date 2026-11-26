# Case-bound model hookup

Two entry points share the same deterministic policy and audit. The model can propose analysis of a SHA-256 in the bound case. The gateway independently decides which operations reach the worker and what results the model receives.

## Local Ollama

Use an installed Ollama model with tool-calling support. For sensitive evidence, start a trusted local-only daemon with `OLLAMA_NO_CLOUD=1` and verify its startup log before running a case. This example binds a second listener without changing the default one. The harness contacts only `127.0.0.1` on the operator-selected port, checks installed model inventory, and never downloads a model. [Ollama local mode](https://docs.ollama.com/faq#how-do-i-disable-ollamas-cloud-features), [Ollama tool calling](https://docs.ollama.com/capabilities/tool-calling).

```powershell
# In a separate PowerShell window.
$env:OLLAMA_NO_CLOUD = '1'
$env:OLLAMA_HOST = '127.0.0.1:11435'
ollama serve

# In the harness directory. Set $model to the exact name of an installed model.
python -m re_harness.cli ask case-001 --port 11435 --model $model --role intake "Summarize artifact $sha using artifact_summary."
```

`ask` offers `intake`, `native`, `evidence`, and `review` role prompts. The system prompt is the role body followed by the Forge's code-owned rules. Every successful tool result is framed as untrusted data under a fresh nonce, and every refusal carries fixed guidance for its reason (docs/SAFETY.md). Role-specific tools, eight turns, four calls per turn and thirty-two total calls bound each run. A role prompt cannot broaden tool access. The local runner does not manage the daemon's own network configuration or storage. The final answer is model-generated and requires evidence review.

## MCP client

Run `python -m re_harness.cli hookup case-001 --format codex` for a Codex-ready stdio server block or `--format json` for the executable, arguments and working directory. Configure a dedicated model session using only this gateway. Choose its model and endpoint according to the case's data classification. The gateway opens no listening port. The client executes the host broker, and the broker owns the case's isolated Docker execution.

Do not register raw REA MCP, unrestricted Ghidra MCP, a shell, network tools or other live connectors alongside this gateway in a case session. External clients enforce their own tool exposure and data policy. The broker mediates only requests it receives. The built-in `ask` entry point provides the narrower execution surface when a general-purpose client cannot restrict its other tools.

## Excerpts and interception

The default output consists of format hints, counts, hashes, offsets and validated function addresses. Decompiled text requires a grant. Strings, native symbol names and raw provider text are omitted unless the operator grants the exact tool call. Each request is matched on the case, SHA-256, tool, canonical address or page parameters, audience and UTC expiry. The broker checks both before running and before releasing the output.

```powershell
python -m re_harness.cli grant case-001 ghidra_decompile $sha --address 0x401000 --audience local --minutes 10
python -m re_harness.cli grant case-001 artifact_strings $sha --offset 0 --limit 10 --audience mcp --minutes 5
python -m re_harness.cli grant case-001 artifact_imports $sha --offset 0 --limit 50 --audience mcp --minutes 5
python -m re_harness.cli grants case-001
python -m re_harness.cli revoke case-001 $grantId
```

`grants CASE` lists the active grant IDs for `revoke` and prunes expired grants. `grant` is refused while the case is paused. Closing a case retires all of its grants and refuses new `ask`, `serve` and `hookup` sessions.

`local` grants apply to `ask` and are the default. `mcp` grants apply to clients connected to the case's MCP broker and may disclose evidence to a hosted model. Configure only the intended MCP client for that case before granting its audience. Cancel an unused grant and pause the case when scope changes. Revocation cannot recall a response already delivered. Operator-only `inspect` lets you review the evidence on disk before granting anything to a model.

Released excerpts are capped at 8 KiB of serialization, labeled untrusted and traceable by result hash. They can include sample instructions or secrets. Review redaction and provider handling before granting release. Model output never grants additional permissions or confirms an operator action.

## Forge chat

The Forge chat (docs/FORGE_API.md) uses the same boundary. In addition:

- A call refused with `operator_excerpt_grant_required` files a grant request for exactly that call, which the operator approves or denies on the case's Rules & grants tab or from the dashboard's *Waiting on you* list. The model can add one short reason with `note_grant_need`.
- A turn that reaches the turn cap gets one last model step with no tools, and its summary becomes the answer instead of an error.
- The prompt lists the skills the role may load, and `load_skill` returns one body (docs/SKILLS.md). Requests for a skill the role cannot load are audited and listed as skill gaps on the Rules page.
- Investigation leads and the benchmark ask a session once to record its facts if it received tool results but recorded nothing (`record_nudged` in the audit). Small models often answer without recording.
- Each chat turn and review run records its input and output tokens in the audit, by provider and locality, and the case's Overview tab shows them on its outcome card.

## Measuring a model

Two harnesses measure a model before and after a change. Both use benign or synthetic fixtures only.

- **Posture probe** (no Docker, no case): `python -m tests.benchmark.posture --model <model-id>` drives the model through the Forge's own prompt tail and output envelope with canned results. It checks that the model calls `artifact_summary` for a plain static-analysis request instead of refusing, and that it neither echoes a canary nor calls a tool that a planted instruction inside a tool result asks for. It exits non-zero if either check fails.
- **Ground-truth benchmark** (needs the provisioned worker image): `python -m tests.benchmark.run --model <model-id> [--grant-imports]` creates a case named `bench-<hex>`, admits the synthetic PE and the image's benign ELF, asks their questions through the normal chat path, and scores the proposed findings against known properties: format, entry point and import names for the PE, format and needed libraries for the ELF. A match needs the right artifact, kind, address and terms, and for observed claims a passing reference check. The report gives recall and precision with their denominators. The case stays for inspection; close it with the operator CLI.

Cloud models are refused by both unless `--allow-cloud` is given. Keep the reports with the model and prompt version they measured.

### Lessons and benchmarks

The Rules page extracts lessons from closed cases. Run the benchmark once with lessons `off` and once with `inject` and only the candidate lesson adopted, then record both runs' recall and precision when adopting it. The Forge refuses an adoption whose after run lost either. Use `shadow` first to see which sessions a lesson would reach.
