# Interception and containment

The control plane applies the task-scoped admission and pre-dispatch review pattern documented by ARTEX to offline artifact analysis. Here the target is an exact SHA-256 in a case manifest and the decision is deterministic. Missing policy state, expired grants, audit errors, provider errors and invalid outputs stop the affected request. [ARTEX interception and operation-review changelog](https://github.com/BaaRai/ARTEX/blob/main/CHANGELOG.md#0313---2026-09-19).

```mermaid
flowchart LR
    M[Case model or MCP client] --> B[Case broker]
    O[Operator CLI] --> P[Case policy and audit]
    P --> B
    B --> D[Apprentice in offline Docker]
    E[Named case evidence volume] -->|read-only for model tools| D
    D --> G[Ghidra MCP, static REA, YARA and capa]
    D --> F[Typed result projection]
    F --> B
```

| Interception point | Enforced behavior |
| --- | --- |
| MCP request | Bounded JSON lines, duplicate-key rejection, exact tool and field names, bounded numeric selectors and per-session call budget |
| Scope | One case, pinned local Linux image, labeled case volume, checked artifact membership and SHA-256, and a fresh pause and closure check |
| Provider | Fixed subprocess arguments and static operations only. No arbitrary provider tool name, command, URL, path or script can be supplied by a model. YARA rules come only from an operator import pinned by SHA-256, with includes off and a module allowlist |
| Container | No external network, ports, host bind mounts, Docker socket, elevated privileges, ambient capabilities or proxy credentials. The root filesystem is read-only. Scratch is bounded and disposable |
| Disclosure | An independent host-side projection validates structured results. Approved excerpts have exact audience and expiry, a data label, and a hard size limit |
| Audit | A durable pre-dispatch record is mandatory. Audit keeps validated selectors, versioned scope decisions and outcomes. It omits sample text, model prompts and credentials |

Published capabilities do not include execution, emulation, debugger attachment, shell commands, arbitrary scripts, program mutation, C2 traffic, network scanning or upload. Treat parser responses as data. The broker admits only a closed set of static operations and carries no model API keys in the analysis container. Docker seccomp is left at its engine default and `no-new-privileges` and dropped capabilities apply to all workers.

The Forge app adds two operator-only paths, and both reach models only through the broker:

- **Sample upload:** an upload streams the bytes to a mode-0600 temporary file in the state directory, ingests them into the case's offline volume through the same operator `ingest` path, then deletes the temporary file. The app never serves sample bytes back.
- **Chat:** the model is a configured endpoint, and the Forge host makes the provider call. Every tool call goes through `server.Broker` with the case's role and tool allowlist, so the model sees only projected results and excerpts covered by an active grant for its audience (`local` for private endpoints, `mcp` for cloud).
- **Cloud models:** a cloud model is Anthropic, a public endpoint, or an Ollama `:cloud` model. It is refused until the case opts in, because projected evidence then leaves the lab.
- **API keys:** keys live in a mode-0600 file under the state directory, are never returned to the browser, and never enter an Apprentice container.

## Residual trust and recovery

Docker isolation shares the Linux kernel. Use an independently isolated guest to host the harness when the case warrants a separate kernel boundary. Docker daemon and WSL operator privileges are trusted. A generic MCP client that has unrelated tools can make requests outside this harness. Use the built-in local client to keep the model's tool surface bounded by construction.

The local case administrator can read or alter case policy and logs. Restrict the operator account and retain copies of case audit and evidence for stronger custody. Each provider import uses a bounded disposable scratch environment. The evidence volume is read-only for model tools. Operator-mode `ingest`, `derive` and persisted `triage` write the case volume, and parser faults in those manual modes have a larger evidence-integrity impact. Verify artifacts and work from reviewed copies where higher custody assurance is needed.

An image snapshot restores the verified tooling state. Container shutdown and scratch disposal leave named evidence volumes available. A revoked grant prevents later releases from that grant. Information already delivered belongs to the receiving client and its data-handling policy.
