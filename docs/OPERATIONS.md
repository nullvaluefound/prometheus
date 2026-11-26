# Forge operator runbook

## Provision and reset

Use [Bootstrap](../README.md) on Windows. The Ubuntu route expects an existing systemd-enabled WSL 2 distro and local Docker-socket access for the distro user. The Desktop route needs its Linux engine. On native amd64 Linux, install Docker Engine with Buildx using the system's package manager and run `python -m re_harness.cli provision --engine linux`. When using a custom local state directory, set `STATIC_RE_STATE_DIR` consistently for the operator CLI and any case model clients.

Provisioning builds with network access to fetch dependencies. Keep cases outside the build context. The image context allowlist excludes evidence, credentials, host state and profiles. Provisioning publishes `baseline.json` after the offline fixture asserts non-root execution, zero capabilities, no Docker socket, loopback-only networking, clean case state and successful provider calls. The selected Docker image ID is authoritative.

```powershell
python -m re_harness.cli snapshot
python -m re_harness.cli blank
python -m re_harness.cli snapshot --output 'D:\RE-Backups\clean-baseline.tar'
python -m re_harness.cli restore 'D:\RE-Backups\clean-baseline.tar' --engine wsl:Ubuntu
```

The optional archive is a Docker image and has an adjacent `.tar.json` SHA-256 manifest. Keep the manifest with the exact archive and restore only a trusted archive. Restore checks image identity and reruns the fixture before activating it. Case volumes and host controls require independent retention. Existing case scopes retain their original image ID. `blank` starts and removes a probe worker with no case mount. Use `init` with a new ID to open an empty case on the verified image. Every analysis call starts in an empty scratch area.

If the build reports disk exhaustion, check the free space on the Windows drive containing the WSL virtual disk or Docker Desktop image. WSL's guest `df` can show free space that the host disk cannot supply. Bring the Docker engine back up and rerun bootstrap after freeing enough space. If Windows or WSL reports storage errors, check guest health before admitting evidence. [Microsoft WSL disk guidance](https://learn.microsoft.com/en-us/windows/wsl/vhd-size).

## Admit and verify evidence

Keep sample files in a restricted staging directory. The harness accepts local regular files and streams bytes to the disconnected worker. Record authorized collection method, UTC time, completeness and transfer identity in your case records. Use a plain source label in `--source`, such as `Operator handoff` or `Internal repository object 42`. Keep auth details out of arguments and files.

```powershell
python -m re_harness.cli init case-001 --title 'Suspicious installer'
python -m re_harness.cli ingest case-001 'C:\Evidence\drop.bin' --source 'Operator handoff' --completeness complete
python -m re_harness.cli status case-001
python -m re_harness.cli verify case-001
python -m re_harness.cli triage case-001 $sha
python -m re_harness.cli derive case-001 $sha base64 0x120 256
```

## Scan with YARA and capa

```powershell
python -m re_harness.cli yara-rules case-001 'C:\Rules\reviewed.yar'
python -m re_harness.cli inspect case-001 yara_scan $sha --output 'C:\Restricted\yara.json'
python -m re_harness.cli inspect case-001 capa_triage $sha --full --output 'C:\Restricted\capa.json'
```

`yara-rules` imports one reviewed rule file of at most 1 MiB into the case. A later import replaces it. The compile error or refused module is printed when a file is rejected. The case audit and `scope.json` record the rules' SHA-256 and rule count. The new rules retire any `yara_scan` grants. Models call `yara_scan` and `capa_triage` with an artifact and a page. Grant either tool with the same `--offset` and `--limit` to release matched bytes or the full capa detail.

`derive` accepts `slice`, `base64`, `gzip` and `zlib`, with a file offset and input byte length. It admits the result under its own hash and records the method and parent. Compressed decoding accepts one complete stream bounded to 64 MiB of output. For a separately reviewed and recovered local file, use `ingest` with `--parent SHA256 --relation 'resource ID and method'`. Policy limits each admitted file to 128 MiB and each case to 256 unique artifacts and 4 GiB of artifact bytes. Track triage and report file growth independently of those artifact limits. A file count or format cap limits coverage, so record it in findings.

Compare manifests by exact release and actual artifacts. Capture partial transfers and conditional alternatives distinctly. Carry out any live collection under the case's authorization in a separate acquisition environment. There is no network acquisition operation in this workspace.

## Capture evidence and report

```powershell
python -m re_harness.cli inspect case-001 ghidra_decompile $sha --address 0x401000 --full --output 'C:\Restricted\function.json'
python -m re_harness.cli finding case-001 --artifact $sha --kind inferred --confidence medium --claim 'Configuration selects a release channel' --evidence 'RVA 0x5120 in native capture'
python -m re_harness.cli verify case-001
python -m re_harness.cli report case-001
python -m re_harness.cli export case-001 report.md 'C:\Restricted\report.md'
python -m re_harness.cli export case-001 evidence.json 'C:\Restricted\evidence.json'
```

`inspect --full` writes the bounded structured provider response to the operator's chosen local path and prints its SHA-256. Cite that path and hash in findings if retained. Export only to a restricted directory. Use the artifact SHA-256 to export its verified bytes under an inert `.bin` extension. Use `<sha256>.triage.json` to export persisted triage. `report` creates an editable scaffold and an evidence JSON record that name the case image and imported YARA rules SHA-256. `--claim` accepts up to 2000 characters and `--evidence` up to 16 entries of 500 characters. `--source` and `--relation` take plain labels of up to 160 characters without URLs. Review defanging and secret handling before distribution.

An `--evidence` value of the form `evidence:<sha256>` names a broker evidence entry in the case's host folder. The CLI refuses the finding if that entry is absent or fails its hash check. The Forge records proposed findings this way, citing each one's evidence.

The ledger is append-only. To correct or withdraw a finding, record its replacement with `--supersedes F0001`. The new finding records the ID it replaces. The target must exist and must not already be superseded. The report keeps superseded findings in a struck-through **Superseded** subsection that names the replacement, and Coverage counts only current findings.

```powershell
python -m re_harness.cli finding case-001 --artifact $sha --kind observed --confidence high --claim 'Configuration selects the beta channel' --evidence 'Offset 0x5120 in native capture' --supersedes F0001
```

Record observed, inferred, corroborated and unknown findings with evidence locators and confidence. Report analyzed artifact coverage, exact versus rolling variants, unresolved conditionals, unavailable files and static limitations. Include pertinent file and process behavior and defensive indicators. Use hashes, transfer details and access-controlled configuration when needed for handoff.

## Close a case

```powershell
python -m re_harness.cli close case-001
python -m re_harness.cli export case-001 report.md 'C:\Restricted\closed-report.md'
```

`close CASE` runs only from the operator CLI. Under the operator lock it verifies the ledger and refuses to close if verification fails. It then generates the report with the case image and YARA rules SHA-256, records `closed` and `closed_utc` in `scope.json`, retires every grant and audits `case_closed` with the report and `case.json` SHA-256 and the retired grant IDs. Closure is irreversible. There is no reopen. Use a new case ID for further work.

The evidence volume is retained. A closed case refuses broker and Forge tool calls, `ask`, `serve`, `hookup`, `ingest`, `derive`, `triage`, `finding`, `report`, `inspect`, `grant`, `revoke`, `pause`, `resume`, `yara-rules` and `init` with `Case is closed`. Broker refusals are audited with the reason `case_closed`. `status`, `verify`, `export`, `cases` and `grants` keep working, and the Forge shows the case page read-only.

## Pause and recover

`pause CASE`, or **Pause case** on the case's Forge page, immediately closes new broker actions and suppresses in-flight model-facing results when the broker next checks scope. Stop the caller to interrupt analysis promptly. `resume CASE` reopens the same validated scope and does not extend grant expiry. `grant` is refused while a case is paused. Audit records are local under `cases/<case-id>/audit.jsonl` inside the operator state directory. Each worker-backed command records `operator_requested` and then `operator_completed` or `operator_failed` with a fixed reason. The records carry the validated `inspect` tool, artifact and arguments, the `export` item, the admitted SHA-256 for `ingest` and `derive` and the capture SHA-256 for `inspect`.

```powershell
python -m re_harness.cli cases
python -m re_harness.cli grants case-001
```

`cases` lists each case's ID, paused, initialized and closed state, image ID and imported YARA rules SHA-256 without changing scope. `grants CASE` lists active grants with their ID, tool, artifact, selector, audience and UTC expiry. It removes expired grants from `scope.json` and audits the removal.

After an interrupted operator command, establish whether its container still exists and whether a mutation already completed before retrying. An interrupted `init` can be rerun. An initialized case with a missing volume is an integrity incident. Restore its original evidence from trusted retention or use a new case ID. If a lock remains, check that its recorded process is gone and that the corresponding Docker worker stopped before removing only that exact lock. Avoid prune, volume removal and factory reset during recovery of an evidence case.

## Investigations in the Forge

An investigation run pursues a case's open questions with the case's chat model. Start it from the case's Investigation tab, after adding at least one open question that names an admitted artifact and a checkable outcome.

- **Steps.** A run is a sequence of short queued tasks: a review of a new proposal, one lead worker session, or one planner round. The next step is queued only while the run is running, so a paused or waiting run holds no task thread. A heartbeat re-queues a running run's step every minute if none is queued.
- **Planner and leads.** The planner reads the case state and adds (at most four a round) or retires leads, and keeps the plan. It calls no sample tools. Each lead worker claims one lead and works it through the broker with the native or evidence role's tools, narrowed by the case's tool allowlist on the Rules tab, recording observations and proposals, and ends with a wrap-up saved on the lead.
- **Completion is yours.** The planner may propose that proposals answer a question, but only proposals whose reference check passed and that cite an artifact the question names. That marks the question *answer proposed*. The run is answered only when you have closed every one of its questions.
- **Waiting on you.** When questions remain but no lead is open, the run waits, showing the planner's stated need on the dashboard. Resume it, message the next lead, add questions or close them.
- **Budgets.** Broker calls, model tokens and active minutes. Active time stops counting while the run is paused or waiting. A session's own calls and tokens count as it goes, so a lead stops at the broker call that would pass a budget. When a budget runs out the run settles: it stops claiming leads, the running lead wraps up at its next broker call, and one final planner turn with no tools writes a summary. The run ends exhausted.
- **Stopping.** Pause and cancel take effect at the next broker call. Pausing the case pauses its run. Cancelling a queued step on the Tasks page pauses its run. A lead that is stopped keeps the observations it wrote. Cancelling a running investigation step from the Tasks page cancels its run.
- **Restarts.** A Forge restart leaves every live run paused, with any interrupted lead open again. Check the run and its grants, then resume it.
- **Reopening.** Only you reopen work, by adding or reopening a question and starting a new run.
