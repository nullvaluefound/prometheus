"""Track static analysis cases. Sample bytes are read as data only."""
import argparse
import contextlib
import datetime
import hashlib
import json
import os
import re
import shutil
import tempfile
import unicodedata
from pathlib import Path

CHUNK = 1024 * 1024
TRIAGE_LIMIT = 128 * CHUNK
STRING_LIMIT = 10000
CLAIM_LIMIT = 2000
EVIDENCE_LIMIT = 16
EVIDENCE_TEXT_LIMIT = 500
KINDS = ("observed", "inferred", "corroborated", "unknown")
# Common file extensions that are also TLDs. Bare names ending in these stay readable.
FILE_TLDS = {"md", "py", "sh", "ps", "so", "rs", "cs", "rb"}
# Bare dotted names are defanged only for ccTLD-length or well-known abused TLDs, not os.path or self.root.
TLDS = {"com", "net", "org", "info", "biz", "xyz", "top", "online", "site", "club", "gov", "edu", "mil", "int",
        "onion", "shop", "store", "app", "dev", "cloud", "live", "tech", "icu", "vip", "win", "bid", "loan", "work",
        "click", "link", "space", "fun", "website", "pro", "name", "mobi", "asia", "tel", "today", "life", "world",
        "email", "host", "press", "rest", "monster", "cyou", "buzz", "sbs", "lol", "quest", "support", "services"}
HOST = re.compile(r"(?<![\w.-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+)([a-z]{2,63})(?![\w-]|\.[a-z0-9])",
                  re.IGNORECASE)
OCTET = r"(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)"
IPV4 = re.compile(rf"(?<![\w.]){OCTET}(?:\.{OCTET}){{3}}(?![\w]|\.\d)")
URL_HOST = re.compile(r"(hxxps?://)([^/\s?#]+)", re.IGNORECASE)


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_text(path, text):
    fd, temporary = tempfile.mkstemp(prefix=".writing-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


def atomic_json(path, value):
    atomic_text(path, json.dumps(value, indent=2, ensure_ascii=True) + "\n")


def hashes(path):
    algorithms = {name: hashlib.new(name) for name in ("sha256", "sha1", "md5")}
    size = 0
    with path.open("rb") as stream:
        for data in iter(lambda: stream.read(CHUNK), b""):
            size += len(data)
            for algorithm in algorithms.values():
                algorithm.update(data)
    return size, {name: value.hexdigest() for name, value in algorithms.items()}


def safe_text(value):
    # Metadata belongs in reports. Preserve readability without control, bidi or line separator codes.
    def clean(c):
        category = unicodedata.category(c)
        if category == "Cf":
            return ""
        if category == "Cs":
            return "?"
        return " " if category in ("Cc", "Zl", "Zp") else c
    return "".join(map(clean, value))


def defang(value):
    text = re.sub(r"https?://", lambda match: "hxxps://" if len(match[0]) == 8 else "hxxp://",
                  safe_text(value), flags=re.IGNORECASE)
    text = URL_HOST.sub(lambda match: match[1] + re.sub(r"(?<!\[)\.(?!\])", "[.]", match[2]), text)
    text = IPV4.sub(lambda match: match[0].replace(".", "[.]"), text)

    def host(match):
        tld = match[2].lower()
        if tld in FILE_TLDS or (len(tld) > 2 and tld not in TLDS):
            return match[0]
        return match[0].replace(".", "[.]")
    return HOST.sub(host, text)


@contextlib.contextmanager
def locked(root):
    root.mkdir(parents=True, exist_ok=True)
    path = root / ".case.lock"
    try:
        fd = os.open(path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    except FileExistsError:
        raise ValueError("Case is locked. Check for an active writer before removing .case.lock")
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(str(os.getpid()))
        yield
    finally:
        path.unlink(missing_ok=True)


def read_case(root):
    case = json.loads((root / "case.json").read_text(encoding="utf-8"))
    if case.get("schema_version") != 1:
        raise ValueError("Unsupported case schema")
    return case


def artifact_path(root, digest):
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise ValueError("Artifact identity must be a lowercase SHA-256")
    path = root / "artifacts" / (digest + ".bin")
    if path.is_symlink() or not path.resolve().is_relative_to(root.resolve()):
        raise ValueError("Artifact path escapes case")
    return path


def known(case, digest):
    if digest not in case["artifacts"]:
        raise ValueError("Unknown artifact SHA-256")


def ingest(root, case, args):
    if args.parent:
        known(case, args.parent)
    if bool(args.parent) != bool(args.relation):
        raise ValueError("--parent and --relation must be supplied together")
    source = args.file.resolve(strict=True)
    if not source.is_file():
        raise ValueError("Source must be a regular file")
    folder = root / "artifacts"
    folder.mkdir(exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix=".ingest-", dir=folder)
    try:
        with os.fdopen(fd, "wb") as output, source.open("rb") as stream:
            shutil.copyfileobj(stream, output, CHUNK)
        staged = Path(temporary)
        size, identities = hashes(staged)
        digest = identities["sha256"]
        if args.parent == digest:
            raise ValueError("Derived artifact has the same bytes as its parent; record a finding instead")
        destination = artifact_path(root, digest)
        if destination.exists():
            if hashes(destination) != (size, identities):
                raise ValueError("Existing artifact store content is corrupt")
        else:
            os.replace(staged, destination)
        record = case["artifacts"].setdefault(digest, dict(size=size, hashes=identities, provenance=[]))
        record["provenance"].append(dict(acquired_utc=now(), source=safe_text(args.source),
                                          completeness=args.completeness, parent=args.parent,
                                          relation=safe_text(args.relation or "")))
        return dict(sha256=digest, size=size, path=str(destination))
    finally:
        Path(temporary).unlink(missing_ok=True)


def pe_metadata(data):
    try:
        import pefile
    except ImportError:
        return dict(limitation="Install pefile on the analysis machine for PE metadata")
    try:
        pe = pefile.PE(data=data)
        imports = {}
        for entry in getattr(pe, "DIRECTORY_ENTRY_IMPORT", []) + getattr(pe, "DIRECTORY_ENTRY_DELAY_IMPORT", []):
            imports[entry.dll.decode("ascii", "replace")] = [
                item.name.decode("ascii", "replace") if item.name else item.ordinal for item in entry.imports
            ]
        fields = {}
        for group in getattr(pe, "FileInfo", []):
            for info in group:
                for table in getattr(info, "StringTable", []):
                    fields.update({k.decode(errors="replace"): v.decode(errors="replace")
                                   for k, v in table.entries.items()})
        return dict(machine=hex(pe.FILE_HEADER.Machine), image_base=hex(pe.OPTIONAL_HEADER.ImageBase),
                    entry_rva=hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint), imports=imports,
                    certificate_size=pe.OPTIONAL_HEADER.DATA_DIRECTORY[4].Size,
                    signature_note="Certificate presence alone does not verify a signature",
                    overlay_offset=pe.get_overlay_data_start_offset(), version_info=fields,
                    sections=[dict(name=s.Name.rstrip(b"\0").decode("ascii", "replace"),
                                   rva=hex(s.VirtualAddress), offset=s.PointerToRawData,
                                   raw_size=s.SizeOfRawData, virtual_size=s.Misc_VirtualSize,
                                   flags=hex(s.Characteristics), entropy=round(s.get_entropy(), 3))
                              for s in pe.sections])
    except Exception as error:
        return dict(parse_error=str(error))


def triage(root, case, digest):
    known(case, digest)
    path = artifact_path(root, digest)
    size, identities = hashes(path)
    if identities != case["artifacts"][digest]["hashes"]:
        raise ValueError("Artifact integrity verification failed")
    if size > TRIAGE_LIMIT:
        raise ValueError("Triage input exceeds 128 MiB; use a bounded format-specific parser")
    result = triage_data(path.read_bytes(), digest, identities)
    folder = root / "analysis"
    folder.mkdir(exist_ok=True)
    atomic_json(folder / (digest + ".triage.json"), result)
    case["artifacts"][digest]["triage"] = "analysis/" + digest + ".triage.json"
    return dict(artifact=digest, format_hint=result["format_hint"], strings=len(result["strings"]),
                strings_truncated=result["strings_truncated"])


def fat_count(data):
    # Java class files share 0xcafebabe; their minor/major version reads as a large arch count.
    if data[:4] not in (b"\xca\xfe\xba\xbe", b"\xca\xfe\xba\xbf") or len(data) < 8:
        return 0
    count = int.from_bytes(data[4:8], "big")
    entry = 20 if data[3] == 0xbe else 32
    return count if 0 < count < 20 and len(data) >= 8 + count * entry else 0


def elf_header(data):
    """Numeric ELF header fields, only when the class and encoding are valid and the header is complete."""
    if data[4] not in (1, 2) or data[5] not in (1, 2) or len(data) < (52 if data[4] == 1 else 64):
        return {}
    endian = "little" if data[5] == 1 else "big"
    width, base = (4, 44) if data[4] == 1 else (8, 56)
    field = lambda offset, size: int.from_bytes(data[offset:offset + size], endian)
    return dict(e_type=field(16, 2), e_entry=field(24, width), phnum=field(base, 2), shnum=field(base + 4, 2))


def triage_data(data, digest, identities):
    kind = "unknown"
    thin = {b"\xfe\xed\xfa\xce": "big", b"\xfe\xed\xfa\xcf": "big",
            b"\xce\xfa\xed\xfe": "little", b"\xcf\xfa\xed\xfe": "little"}.get(data[:4])
    if data.startswith(b"MZ"):
        kind = "PE candidate"
    elif data.startswith(b"\x7fELF"):
        kind = "ELF"
    elif thin:
        kind = "Mach-O"
    elif fat_count(data):
        kind = "Mach-O universal"
    elif data.startswith(b"PK\x03\x04"):
        kind = "ZIP candidate"
    elif data.startswith(b"#!"):
        kind = "script"
    strings = []
    truncated = False
    for pattern, codec in ((rb"[ -~]{6,}", "ascii"), (rb"(?:[ -~]\x00){6,}", "utf-16le")):
        for match in re.finditer(pattern, data):
            start, end = match.span()
            # A printable byte before the first unit means that unit ends an ASCII run, as in b"world\x00".
            if codec == "utf-16le" and start and 0x20 <= data[start - 1] <= 0x7e:
                start += 2
                if end - start < 12:
                    continue
            if len(strings) >= STRING_LIMIT:
                truncated = True
                break
            strings.append(dict(offset=start, encoding=codec,
                                text=data[start:min(end, start + 4096)].decode(codec),
                                full_byte_length=end - start))
    strings.sort(key=lambda item: item["offset"])
    result = dict(artifact=digest, created_utc=now(), size=len(data), format_hint=kind,
                  hashes=identities, strings=strings, strings_truncated=truncated,
                  limits=dict(input_bytes=TRIAGE_LIMIT, strings=STRING_LIMIT, string_bytes=4096))
    if kind == "PE candidate":
        result["pe"] = pe_metadata(data)
    if kind == "ELF" and len(data) >= 20:
        endian = "little" if data[5] == 1 else "big"
        result["elf"] = dict(elf_class=data[4], data_encoding=data[5],
                             machine=int.from_bytes(data[18:20], endian))
        result["elf"].update(elf_header(data))
    if kind == "Mach-O" and len(data) >= 16:
        result["macho"] = dict(endian=thin, bits=64 if data[0] == 0xcf or data[3] == 0xcf else 32,
                               cputype=int.from_bytes(data[4:8], thin), filetype=int.from_bytes(data[12:16], thin))
    if kind == "Mach-O universal":
        result["macho"] = dict(fat_arch_count=fat_count(data), fat64=data[3] == 0xbf)
    return result


def verify(root, case):
    problems = []
    for digest, record in case["artifacts"].items():
        try:
            size, identities = hashes(artifact_path(root, digest))
            if size != record["size"] or identities != record["hashes"]:
                problems.append(dict(artifact=digest, error="Hash or size mismatch"))
            for provenance in record["provenance"]:
                parent = provenance["parent"]
                if parent and parent not in case["artifacts"]:
                    problems.append(dict(artifact=digest, error="Missing parent"))
        except (OSError, ValueError) as error:
            problems.append(dict(artifact=digest, error=str(error)))
    return dict(ok=not problems, checked=len(case["artifacts"]), problems=problems)


def read_triage(root, digest, record):
    # Persisted triage is worker output over sample bytes; read only the expected file and fields.
    if "triage" not in record:
        return None, []
    if record["triage"] != "analysis/" + digest + ".triage.json":
        return None, ["Triage record path is outside the expected location"]
    try:
        value = json.loads((root / record["triage"]).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None, ["Recorded triage is unreadable"]
    if not isinstance(value, dict):
        return None, ["Recorded triage is malformed"]
    notes = []
    if value.get("strings_truncated") is True:
        limit = value.get("limits", {}).get("strings") if isinstance(value.get("limits"), dict) else None
        notes.append("String scan truncated" + (f" at {limit} strings" if type(limit) is int else ""))
    pe = value.get("pe")
    if isinstance(pe, dict):
        for key in ("limitation", "parse_error"):
            if isinstance(pe.get(key), str):
                notes.append("PE " + key.replace("_", " ") + ": " + defang(pe[key][:500]))
    hint = value.get("format_hint")
    return (defang(hint[:64]) if isinstance(hint, str) else None), notes


def report(root, case, image=None, yara_rules=None):
    result = verify(root, case)
    if not result["ok"]:
        raise ValueError("Integrity verification failed; repair or document it before reporting")
    artifacts, findings = case["artifacts"], case["findings"]
    ledger = hashlib.sha256((root / "case.json").read_bytes()).hexdigest()
    lines = ["# " + defang(case["title"]), "",
             "Static analysis report scaffold. Quoted text is untrusted sample-derived evidence and is defanged.", "",
             "- Generated " + now(), "- Case created " + defang(case.get("created_utc", "unknown")),
             "- Mode " + defang(case["mode"]),
             "- Worker image " + (f"`{image}`" if image else "not recorded"),
             "- YARA rules SHA-256 " + (f"`{yara_rules}`" if yara_rules else "not recorded"),
             "", "## Assessment", "",
             "_Analyst: state the overall assessment, its confidence and the deciding evidence._",
             "", "## Artifacts", ""]
    limitations, partial = [], []
    for digest, item in artifacts.items():
        hint, notes = read_triage(root, digest, item)
        limitations.extend(f"- `{digest}`: {note}" for note in notes)
        lines.extend([f"### `{digest}`", "", f"- MD5 `{item['hashes']['md5']}`",
                      f"- SHA-1 `{item['hashes']['sha1']}`", f"- Size {item['size']} bytes",
                      "- Format hint " + (hint or "not triaged")])
        for provenance in item["provenance"]:
            lines.append("- Source " + defang(provenance["source"]) + "; " + defang(provenance["completeness"]) +
                         "; acquired " + defang(provenance["acquired_utc"]))
            if provenance["parent"]:
                lines.append("  - Parent `" + provenance["parent"] + "`, " + defang(provenance["relation"]))
        if all(p["completeness"] != "complete" for p in item["provenance"]):
            partial.append(digest)
        lines.append("")
    if not artifacts:
        lines.extend(["No artifacts are recorded.", ""])
    cited = {digest for finding in findings for digest in finding["artifacts"]}
    covered = [digest for digest in artifacts if digest in cited]
    uncovered = [digest for digest in artifacts if digest not in cited]
    lines.extend(["## Coverage", "", f"- {len(covered)} of {len(artifacts)} artifacts are cited by findings"])
    lines.extend(f"  - With findings `{digest}`" for digest in covered)
    lines.extend(f"  - Without findings `{digest}`" for digest in uncovered)
    lines.extend(f"- Partial or unknown completeness `{digest}`" for digest in partial)
    lines.extend(["- Exact versus rolling variants: _Analyst: state which hashes are exact and which may roll._",
                  "- Unresolved conditionals: _Analyst: list branches, checks and paths not established statically._",
                  "- Unavailable files: _Analyst: list referenced payloads, modules or configs not acquired._",
                  "", "## Findings", ""])
    for kind in KINDS[:3]:
        group = [finding for finding in findings if finding["kind"] == kind]
        if group:
            lines.extend(["### " + kind.capitalize(), ""])
            lines.extend(line for finding in group for line in finding_lines(finding))
            lines.append("")
    if not any(finding["kind"] != "unknown" for finding in findings):
        lines.extend(["Analysis findings remain to be recorded.", ""])
    lines.extend(["## Unknowns", ""])
    unknown = [line for finding in findings if finding["kind"] == "unknown" for line in finding_lines(finding)]
    lines.extend(unknown or ["No unknowns are recorded."])
    lines.extend(["", "## Limitations", "",
                  "- Static only. Samples were not executed, emulated or debugged, and no live destination was used.",
                  "- _Analyst: record parser, loader, packer and coverage limits._"])
    lines.extend(limitations)
    lines.extend(["", "## Indicators", "",
                  "_Analyst: list justified defensive indicators with their finding IDs. Keep them defanged._",
                  "", "## Ledger verification", "",
                  f"- Passed: {result['checked']} artifacts checked, {len(result['problems'])} problems",
                  f"- case.json SHA-256 `{ledger}`", "- Evidence record evidence.json", ""])
    atomic_text(root / "report.md", "\n".join(lines))
    atomic_json(root / "evidence.json", case)
    return dict(report=str(root / "report.md"), evidence=str(root / "evidence.json"), case_sha256=ledger)


def finding_lines(finding):
    yield f"- {finding['id']} [{finding['confidence']}] " + defang(finding["claim"])
    yield "  - Artifacts " + ", ".join(f"`{digest}`" for digest in finding["artifacts"])
    yield "  - Recorded " + defang(finding["created_utc"])
    yield from ("  - Evidence " + defang(value) for value in finding["evidence"])


def pattern(expression, label):
    def check(value):
        if not re.fullmatch(expression, value):
            raise argparse.ArgumentTypeError(label)
        return value
    return check


def record_finding(case, args):
    for digest in args.artifact:
        known(case, digest)
    claim, evidence = safe_text(args.claim), [safe_text(value) for value in args.evidence]
    if len(claim) > CLAIM_LIMIT or len(evidence) > EVIDENCE_LIMIT or any(
            len(value) > EVIDENCE_TEXT_LIMIT for value in evidence):
        raise ValueError(f"Finding exceeds {CLAIM_LIMIT} claim characters or "
                         f"{EVIDENCE_LIMIT} evidence items of {EVIDENCE_TEXT_LIMIT} characters")
    result = dict(id="F" + str(len(case["findings"]) + 1).zfill(4), created_utc=now(),
                  artifacts=list(dict.fromkeys(args.artifact)), kind=args.kind, confidence=args.confidence,
                  claim=claim, evidence=evidence)
    case["findings"].append(result)
    return result


def parser():
    cli = argparse.ArgumentParser(description=__doc__)
    sub = cli.add_subparsers(dest="command", required=True)
    for name in ("init", "ingest", "triage", "finding", "verify", "status", "report"):
        child = sub.add_parser(name)
        child.add_argument("case", type=Path)
        if name == "init":
            child.add_argument("--title", required=True)
        elif name == "ingest":
            child.add_argument("file", type=Path)
            child.add_argument("--source", required=True, help="Sanitized source, without credentials")
            child.add_argument("--parent")
            child.add_argument("--relation")
            child.add_argument("--completeness", choices=("complete", "partial", "unknown"), default="unknown")
        elif name == "triage":
            child.add_argument("artifact")
        elif name == "finding":
            child.add_argument("--artifact", action="append", required=True)
            child.add_argument("--kind", choices=KINDS, required=True)
            child.add_argument("--confidence", choices=("low", "medium", "high"), required=True)
            child.add_argument("--claim", required=True)
            child.add_argument("--evidence", action="append", required=True)
        elif name == "report":
            child.add_argument("--image", type=pattern(r"sha256:[0-9a-f]{64}", "expected sha256:<64 hex>"))
            child.add_argument("--yara-rules-sha256", type=pattern(r"[0-9a-f]{64}", "expected 64 lowercase hex"))
    return cli


def main(argv=None):
    cli = parser()
    args = cli.parse_args(argv)
    root = args.case.resolve()
    try:
        lock = contextlib.nullcontext() if args.command in ("status", "verify") else locked(root)
        with lock:
            path = root / "case.json"
            if args.command == "init":
                if path.exists():
                    raise ValueError("Case already exists")
                case = dict(schema_version=1, title=safe_text(args.title), created_utc=now(),
                            mode="static", artifacts={}, findings=[])
                result = dict(case=str(root))
            else:
                case = read_case(root)
                if args.command == "ingest":
                    result = ingest(root, case, args)
                elif args.command == "triage":
                    result = triage(root, case, args.artifact)
                elif args.command == "finding":
                    result = record_finding(case, args)
                elif args.command == "verify":
                    result = verify(root, case)
                elif args.command == "report":
                    result = report(root, case, args.image, args.yara_rules_sha256)
                else:
                    result = dict(title=case["title"], mode=case["mode"], artifacts=case["artifacts"],
                                  findings=case["findings"])
            if args.command in ("init", "ingest", "triage", "finding"):
                atomic_json(path, case)
        print(json.dumps(result, indent=2, ensure_ascii=True))
        return 1 if args.command == "verify" and not result["ok"] else 0
    except (OSError, ValueError, KeyError) as error:
        cli.exit(2, "Error: " + str(error) + "\n")


if __name__ == "__main__":
    raise SystemExit(main())
