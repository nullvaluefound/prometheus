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
from pathlib import Path

CHUNK = 1024 * 1024
TRIAGE_LIMIT = 128 * CHUNK
STRING_LIMIT = 10000


def now():
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def atomic_json(path, value):
    fd, temporary = tempfile.mkstemp(prefix=".writing-", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(value, stream, indent=2, ensure_ascii=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        Path(temporary).unlink(missing_ok=True)


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
    # Metadata belongs in reports. Preserve readability without terminal control codes.
    return "".join(c if c >= " " and c != "\x7f" else " " for c in value)


def defang(value):
    return re.sub(r"https?://", lambda match: "hxxps://" if len(match[0]) == 8 else "hxxp://",
                  safe_text(value), flags=re.IGNORECASE)


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


def triage_data(data, digest, identities):
    kind = "unknown"
    if data.startswith(b"MZ"):
        kind = "PE candidate"
    elif data.startswith(b"\x7fELF"):
        kind = "ELF"
    elif data.startswith(b"PK\x03\x04"):
        kind = "ZIP candidate"
    elif data.startswith(b"#!"):
        kind = "script"
    strings = []
    truncated = False
    for pattern, codec in ((rb"[ -~]{6,}", "ascii"), (rb"(?:[ -~]\x00){6,}", "utf-16le")):
        for match in re.finditer(pattern, data):
            if len(strings) >= STRING_LIMIT:
                truncated = True
                break
            start, end = match.span()
            strings.append(dict(offset=match.start(), encoding=codec,
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


def report(root, case):
    result = verify(root, case)
    if not result["ok"]:
        raise ValueError("Integrity verification failed; repair or document it before reporting")
    lines = ["# " + defang(case["title"]), "", "Static analysis evidence scaffold", "",
             "Generated " + now(), "", "## Artifacts", ""]
    for digest, item in case["artifacts"].items():
        lines.extend([f"- SHA-256 `{digest}`, {item['size']} bytes"])
        for provenance in item["provenance"]:
            lines.append("  - Source " + defang(provenance["source"]) + "; " + provenance["completeness"])
            if provenance["parent"]:
                lines.append("  - Parent `" + provenance["parent"] + "`, " + defang(provenance["relation"]))
    lines.extend(["", "## Findings", ""])
    for finding in case["findings"]:
        lines.extend([f"- {finding['id']} [{finding['kind']}, {finding['confidence']}] " + defang(finding["claim"])])
        lines.extend("  - Evidence " + defang(value) for value in finding["evidence"])
    if not case["findings"]:
        lines.append("Analysis findings remain to be recorded.")
    (root / "report.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    atomic_json(root / "evidence.json", case)
    return dict(report=str(root / "report.md"), evidence=str(root / "evidence.json"))


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
            child.add_argument("--kind", choices=("observed", "inferred", "corroborated", "unknown"), required=True)
            child.add_argument("--confidence", choices=("low", "medium", "high"), required=True)
            child.add_argument("--claim", required=True)
            child.add_argument("--evidence", action="append", required=True)
    return cli


def main():
    cli = parser()
    args = cli.parse_args()
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
                    for digest in args.artifact:
                        known(case, digest)
                    result = dict(id="F" + str(len(case["findings"]) + 1).zfill(4), created_utc=now(),
                                  artifacts=args.artifact, kind=args.kind, confidence=args.confidence,
                                  claim=safe_text(args.claim), evidence=[safe_text(e) for e in args.evidence])
                    case["findings"].append(result)
                elif args.command == "verify":
                    result = verify(root, case)
                elif args.command == "report":
                    result = report(root, case)
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
