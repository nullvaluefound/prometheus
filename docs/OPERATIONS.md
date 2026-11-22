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

`derive` accepts `slice`, `base64`, `gzip` and `zlib`, with a file offset and input byte length. It admits the result under its own hash and records the method and parent. Compressed decoding accepts one complete stream bounded to 64 MiB of output. For a separately reviewed and recovered local file, use `ingest` with `--parent SHA256 --relation 'resource ID and method'`. Policy limits each admitted file to 128 MiB and each case to 256 unique artifacts and 4 GiB of artifact bytes. Track triage and report file growth independently of those artifact limits. A file count or format cap limits coverage, so record it in findings.

Compare manifests by exact release and actual artifacts. Capture partial transfers and conditional alternatives distinctly. Carry out any live collection under the case's authorization in a separate acquisition environment. There is no network acquisition operation in this workspace.

## Capture evidence and close

```powershell
python -m re_harness.cli inspect case-001 ghidra_decompile $sha --address 0x401000 --full --output 'C:\Restricted\function.json'
python -m re_harness.cli finding case-001 --artifact $sha --kind inferred --confidence medium --claim 'Configuration selects a release channel' --evidence 'RVA 0x5120 in native capture'
python -m re_harness.cli verify case-001
python -m re_harness.cli report case-001
python -m re_harness.cli export case-001 report.md 'C:\Restricted\report.md'
python -m re_harness.cli export case-001 evidence.json 'C:\Restricted\evidence.json'
```

`inspect --full` writes the bounded structured provider response to the operator's chosen local path and prints its SHA-256. Cite that path and hash in findings if retained. Export only to a restricted directory. Use the artifact SHA-256 to export its verified bytes under an inert `.bin` extension. Use `<sha256>.triage.json` to export persisted triage. `report` creates an editable scaffold and an evidence JSON record. Review defanging and secret handling before distribution.

Record observed, inferred, corroborated and unknown findings with evidence locators and confidence. Report analyzed artifact coverage, exact versus rolling variants, unresolved conditionals, unavailable files and static limitations. Include pertinent file and process behavior and defensive indicators. Use hashes, transfer details and access-controlled configuration when needed for handoff.

## Pause and recover

`pause CASE` immediately closes new broker actions and suppresses in-flight model-facing results when the broker next checks scope. Stop the caller to interrupt analysis promptly. `resume CASE` reopens the same validated scope and does not extend expiry. Audit records are local under `cases/<case-id>/audit.jsonl` inside the operator state directory.

After an interrupted operator command, establish whether its container still exists and whether a mutation already completed before retrying. An interrupted `init` can be rerun. An initialized case with a missing volume is an integrity incident. Restore its original evidence from trusted retention or use a new case ID. If a lock remains, check that its recorded process is gone and that the corresponding Docker worker stopped before removing only that exact lock. Avoid prune, volume removal and factory reset during recovery of an evidence case.
