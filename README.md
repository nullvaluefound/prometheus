# Prometheus

Prometheus is a defensive static malware reverse-engineering harness. The **Forge** is the operator workspace. **Apprentices** are disposable, offline Docker workers that inspect files with Ghidra MCP, REA, capa and YARA. The operator admits evidence and controls what gets shared with a model.

## Start here

Run these commands from this directory in PowerShell. Initial setup needs Python 3.10 or newer, an amd64 Windows machine, and about 8 GiB of free space on the Docker storage drive for image layers and build cache.

```powershell
# Install or reuse Docker Engine in an existing systemd-enabled Ubuntu WSL 2 distribution.
.\scripts\Bootstrap.ps1 -WslDistribution Ubuntu

# Or install or reuse Docker Desktop with Linux containers.
.\scripts\Bootstrap.ps1
```

Bootstrap builds an image from the pinned tool inputs, tests isolation and the Ghidra MCP, REA, YARA and capa providers with a benign ELF, and records the verified image ID as the clean baseline. Windows WSL keeps the image and case volumes inside the distribution. Host-side policy and audit files live under `%USERPROFILE%\.static-re-harness`.

```powershell
python -m re_harness.cli blank
python -m re_harness.cli init case-001 --title 'Suspicious installer'
python -m re_harness.cli ingest case-001 'C:\Evidence\sample.bin' --source 'Operator evidence handoff' --completeness complete
python -m re_harness.cli hookup case-001
```

Use the SHA-256 from intake for subsequent analysis. `blank` starts a new worker with no evidence volume attached. A new case ID starts a new evidence volume. Each analysis request gets fresh scratch space, while the case volume retains admitted evidence.

| Guide | Use it for |
| --- | --- |
| [Operator runbook](docs/OPERATIONS.md) | Install, admit and derive artifacts, export evidence, preserve the baseline and recover from a failed run |
| [Model hookup](docs/MODELS.md) | Use local Ollama or a case-bound MCP client and grant a specific evidence excerpt |
| [Interception and containment](docs/SAFETY.md) | Check exactly what the gateway and Docker enforce and how to pause a case |
| [Tool inventory](docs/TOOLS.md) | Identify required dependencies, exposed capabilities and optional analyst tools |
| [Forge deployment](docs/DEPLOY.md) | Configure a Linux VM, operator accounts, the Forge app and a VPN-backed reverse proxy |
| [Forge API](docs/FORGE_API.md) | The JSON API behind the Forge app: cases, uploads, tools, grants, chat, models and tasks |
| [Case instructions](AGENTS.md) | Choose the appropriate analyst or operator role |

Run `python -m unittest discover -s tests` for the host-side checks. Run `python -m tests.smoke` after provisioning for a disposable end-to-end case using the built-in benign fixture.
