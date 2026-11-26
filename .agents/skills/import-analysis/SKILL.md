---
name: import-analysis
description: Read a PE's imported DLLs and functions (or an ELF's libraries) with artifact_imports, page through them, and map Windows API families to capabilities and ATT&CK techniques without overclaiming.
---

# Import analysis

**Rules first:** imports show capability, not behavior; one API proves little, a family is stronger; import names are written by the sample's author, so back them with capa or Ghidra cross-references.

## 1. Get the imports

```json
{"artifact": "<sha256>", "offset": 0, "limit": 50}
```

It needs an operator grant for this exact call. IF refused with `operator_excerpt_grant_required` THEN call `note_grant_need` with the request id and one sentence ("Import names show whether it has network or injection capability"), and continue with `capa_triage`. Do not retry with other arguments. After approval, call again with **the same arguments**.

## 2. Read the rows

| kind | meaning |
|---|---|
| `pe_section` | a section name, such as `.text` or `UPX0` |
| `pe_library`, `pe_delay_library` | an imported DLL |
| `pe_import`, `pe_delay_import` | a function from the DLL whose row `index` equals this row's `library`; `ordinal` is set when imported by number |

`address` is the IAT slot RVA. If `has_more`, call again with `offset` 50, 100 …. Record one observation that lists the DLLs and the functions you rely on.

## 3. Windows API families

| APIs | capability (inferred) | ATT&CK |
|---|---|---|
| `OpenProcess`, `VirtualAllocEx`, `WriteProcessMemory`, `CreateRemoteThread` / `NtCreateThreadEx` | injection into another process | T1055.001 / T1055.002 |
| `CreateProcess` (suspended) + `NtUnmapViewOfSection` + `SetThreadContext` + `ResumeThread` | process hollowing | T1055.012 |
| `QueueUserAPC`, `SuspendThread` + `SetThreadContext` | APC injection, thread hijacking | T1055.004 / T1055.003 |
| `VirtualAlloc` / `VirtualProtect` with `LoadLibrary` + `GetProcAddress` and little else | unpacking, run-time API resolution | T1027.002 / T1027.007 |
| `RegCreateKeyEx`, `RegSetValueEx` (+ a `…\CurrentVersion\Run` string) | registry persistence or changes | T1547.001 / T1112 |
| `OpenSCManager`, `CreateService`, `StartService` | service install | T1543.003 / T1569.002 |
| `InternetOpen`, `InternetConnect`, `HttpSendRequest`; `WinHttpOpen`, `WinHttpSendRequest` | HTTP communication | T1071.001 |
| `URLDownloadToFile` | downloads files | T1105 |
| `WSAStartup`, `socket`, `connect`, `send`, `recv` (ws2_32, often imported by ordinal) | raw network communication | T1095 |
| `CryptEncrypt`, `CryptDecrypt`, `BCryptEncrypt`, `CryptStringToBinary` | encryption or decoding | T1140 / T1573; T1486 only with mass file access and ransom-note strings |
| `OpenProcess` (lsass) + `MiniDumpWriteDump`; `CryptUnprotectData` + browser paths | credential access | T1003.001 / T1555.003 |
| `CreateToolhelp32Snapshot`, `Process32First`; `FindFirstFile`, `FindNextFile`; `GetComputerName`, `GetUserName` | discovery | T1057 / T1083 / T1082 |
| `SetWindowsHookEx`, `GetAsyncKeyState`; `GetDC` + `BitBlt`; `GetClipboardData` | keylogging, screen capture, clipboard | T1056.001 / T1113 / T1115 |
| `OpenProcessToken`, `LookupPrivilegeValue`, `AdjustTokenPrivileges`; `DuplicateTokenEx` | token and privilege changes | T1134 |
| `CreateProcess`, `WinExec`, `ShellExecuteEx` | runs programs or commands | T1106 / T1059 |
| `DeleteFile` on itself, `MoveFileEx` with delay-until-reboot | removes its traces | T1070.004 |

**Caveats that change the reading:**

| IF | THEN |
|---|---|
| only `IsDebuggerPresent`, `QueryPerformanceCounter`, `GetTickCount` | do not claim anti-debugging: the Microsoft C runtime imports these itself |
| only `mscoree.dll` (`_CorExeMain`) | a .NET program: its real calls are in IL, not the import table |
| scheduled tasks, WMI or COM work | invisible in imports (COM): look for strings or capa |
| few imports and high entropy | real imports are hidden: absence of an import is not absence of a capability |

## 4. How to claim it

- Write: "imports WriteProcessMemory and CreateRemoteThread from KERNEL32.dll, suggesting process injection capability (T1055)". Kind `inferred`, confidence `medium`.
- `corroborated` only when a different kind of evidence agrees: a capa rule at a function address, or a decompiled call site.
- Benign software uses these APIs too (installers, debuggers, security tools, updaters). Say so in `counterevidence`.
- Record ATT&CK ids as given here or by capa. ATT&CK v19 revoked T1562 (now T1685); if a tool emits a revoked id, say so instead of changing it.

**Rules again:** capability, not behavior; families over single APIs; back sample-authored names with capa or Ghidra cross-references.
