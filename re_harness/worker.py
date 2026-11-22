"""Container entry point. All sample handling is byte-oriented and offline."""

import hashlib
import json
import os
import shutil
import stat
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

from . import case, decoding, policy, providers

ROOT = Path("/case")
FIXTURE = Path("/opt/fixtures/benign.elf")
MAX_CASE_ARTIFACTS = 256
MAX_CASE_BYTES = 4 * 1024 * 1024 * 1024


def emit(value):
    print(json.dumps(value, ensure_ascii=True, allow_nan=False))


def artifact(digest):
    data = case.read_case(ROOT)
    case.known(data, digest)
    path = case.artifact_path(ROOT, digest)
    info = path.stat()
    if not stat.S_ISREG(info.st_mode) or info.st_size > policy.MAX_ARTIFACT:
        raise ValueError("artifact_type_or_size")
    size, identities = case.hashes(path)
    if identities["sha256"] != digest or size != data["artifacts"][digest]["size"]:
        raise ValueError("artifact_integrity")
    return path, size, identities


def excerpt(value):
    raw = json.dumps(value, ensure_ascii=True, allow_nan=False, sort_keys=True)
    return {"trust": "untrusted_sample_derived_data", "text": raw[:policy.MAX_EXCERPT],
            "sha256_of_serialized_result": hashlib.sha256(raw.encode("ascii")).hexdigest(),
            "serialized_bytes": len(raw), "truncated": len(raw) > policy.MAX_EXCERPT}


def triage(name, path, digest, identities, options):
    detail = case.triage_data(path.read_bytes(), digest, identities)
    if name == "artifact_strings":
        start, limit = options["offset"], options["limit"]
        rows = detail["strings"][start:start + limit]
        safe_rows = [{key: row[key] for key in ("offset", "encoding", "full_byte_length")} for row in rows]
        return {"rows": safe_rows, "has_more": start + len(rows) < len(detail["strings"]),
                "scan_truncated": detail["strings_truncated"]}, rows
    info = {key: detail[key] for key in ("size", "format_hint", "strings_truncated")}
    info["strings_count"] = len(detail["strings"])
    if "elf" in detail:
        info["elf"] = detail["elf"]
    if "pe" in detail:
        pe = detail["pe"]
        info["pe"] = {"parsed": "sections" in pe, "sections_count": len(pe.get("sections", [])),
                      "import_libraries_count": len(pe.get("imports", {})),
                      "certificate_bytes": pe.get("certificate_size", 0)}
    return info, None


def analyze(request, full=False):
    if set(request) != {"tool", "arguments", "excerpt"} or type(request["excerpt"]) is not bool:
        raise ValueError("invalid_worker_request")
    name = request["tool"]
    options = policy.validate(name, request["arguments"])
    digest = options.pop("artifact")
    display_excerpt = request["excerpt"]
    if name in policy.EXCERPT_ONLY and not display_excerpt:
        raise ValueError("excerpt_grant_required")
    path, size, hashes = artifact(digest)
    if name.startswith("artifact_"):
        summary, raw = triage(name, path, digest, hashes, options)
    else:
        raw = providers.run(name, path, options)
        if name in ("ghidra_functions", "ghidra_xrefs"):
            summary = providers.ghidra_index(name, raw, options["limit"])
        else:
            summary = {"provider_response": "structured", "top_level_fields": len(raw)}
    result = {"tool": name, "artifact": digest, "artifact_bytes": size, "summary": summary}
    if display_excerpt and raw is not None:
        result["evidence_excerpt"] = excerpt(raw)
    if full and raw is not None:
        result["evidence"] = {"trust": "untrusted_sample_derived_data", "result": raw}
    return result


def case_command(command, *args):
    process = subprocess.run([sys.executable, "-m", "re_harness.case", command, str(ROOT), *args],
                             stdin=subprocess.DEVNULL, check=False)
    return process.returncode


def ingest(args):
    with tempfile.TemporaryDirectory(prefix="stage-") as stage:
        target = Path(stage) / "input.bin"
        total = 0
        with target.open("xb") as output:
            for chunk in iter(lambda: sys.stdin.buffer.read(1024 * 1024), b""):
                total += len(chunk)
                if total > policy.MAX_ARTIFACT:
                    raise ValueError("artifact_too_large")
                output.write(chunk)
        return store(target, args)


def store(target, args):
    records = case.read_case(ROOT)["artifacts"]
    size, identities = case.hashes(target)
    if identities["sha256"] not in records and (len(records) >= MAX_CASE_ARTIFACTS or size + sum(
            item["size"] for item in records.values()) > MAX_CASE_BYTES):
        raise ValueError("case_artifact_limit")
    return case_command("ingest", str(target), *args)


def derive(parent, method, offset_text, length_text):
    source, size, _ = artifact(parent)
    offset, length = int(offset_text), int(length_text)
    if not (0 <= offset <= size and 1 <= length <= decoding.INPUT_CAP and offset + length <= size):
        raise ValueError("decode_range_outside_artifact")
    with source.open("rb") as stream:
        stream.seek(offset)
        recovered = decoding.decode(method, stream.read(length))
    with tempfile.TemporaryDirectory(prefix="derived-") as directory:
        target = Path(directory) / "derived.bin"
        target.write_bytes(recovered)
        return store(target, ["--source", "Bounded offline derivation", "--parent", parent,
                              "--relation", f"{method} at file offset {offset:#x}, input length {length}",
                              "--completeness", "unknown"])


def export_file(name):
    if name == "artifact":
        raise ValueError("artifact_digest_required")
    if policy.match(name, policy.DIGEST):
        path, _, _ = artifact(name)
    elif name in ("case.json", "report.md", "evidence.json"):
        path = ROOT / name
    elif name.endswith(".triage.json") and policy.match(name[:-12], policy.DIGEST):
        path = ROOT / "analysis" / name
    else:
        raise ValueError("invalid_export")
    if path.is_symlink() or not path.resolve().is_relative_to(ROOT) or not path.is_file():
        raise ValueError("invalid_export_file")
    with path.open("rb") as source:
        shutil.copyfileobj(source, sys.stdout.buffer)


def selftest(full):
    # A golden input built from the two-line source in the Dockerfile, opened as data.
    assert os.geteuid() == 65532 and os.getegid() == 65532
    status = Path("/proc/self/status").read_text()
    assert "CapEff:\t0000000000000000" in status and "NoNewPrivs:\t1" in status
    assert set(os.listdir("/sys/class/net")) == {"lo"}
    assert not os.access("/opt/harness", os.W_OK)
    assert not Path("/var/run/docker.sock").exists()
    assert all(not value for name, value in os.environ.items() if name.lower().endswith("_proxy"))
    assert os.access("/tmp", os.W_OK)
    assert not (ROOT / "case.json").exists()
    result = {"blank": True, "offline": True, "uid": os.geteuid(), "fixture": "compiled ELF"}
    if full:
        functions = providers.run("ghidra_functions", FIXTURE, {"offset": 0, "limit": 50}, diagnostics=True)
        index = providers.ghidra_index("ghidra_functions", functions, 50)
        example = next(row for row in functions["items"] if row.get("name") == "example")
        address = next(value for field in ("address", "entry", "entry_point")
                       if (value := providers.safe_address(example.get(field))))
        crossrefs = providers.run("ghidra_xrefs", FIXTURE, {"address": address, "offset": 0, "limit": 20}, diagnostics=True)
        native_ghidra = providers.run("ghidra_decompile", FIXTURE, {"address": address}, diagnostics=True)
        native_rea = providers.run("rea_inspect", FIXTURE, {}, diagnostics=True)
        rea_decompile = providers.run("rea_decompile", FIXTURE, {"address": address}, diagnostics=True)
        assert index["rows"] and providers.ghidra_index("ghidra_xrefs", crossrefs, 20)["rows"]
        assert "example" in json.dumps(native_ghidra) and "example" in json.dumps(rea_decompile)
        assert native_rea
        result.update(ghidra_mcp="function index, xrefs, decompilation", rea="native inspect and decompilation")
    emit(result)


def main():
    mode, *args = sys.argv[1:]
    try:
        if mode in ("analyze", "capture"):
            request = sys.stdin.buffer.read(policy.MAX_LINE + 1)
            if len(request) > policy.MAX_LINE:
                raise ValueError("request_too_large")
            emit(analyze(json.loads(request), full=mode == "capture"))
        elif mode == "ingest":
            return ingest(args)
        elif mode == "derive":
            return derive(*args)
        elif mode == "export":
            export_file(*args)
        elif mode == "fixture":
            if (ROOT / "case.json").exists():
                raise ValueError("fixture_requires_blank_worker")
            sys.stdout.buffer.write(FIXTURE.read_bytes())
        elif mode in ("blank", "selftest"):
            selftest(mode == "selftest")
        elif mode == "case" and args and args[0] in {"init", "status", "verify", "triage", "finding", "report"}:
            return case_command(*args)
        else:
            raise ValueError("unknown_worker_mode")
        return 0
    except Exception:
        # Provider exceptions and stderr can contain sample-derived text or paths.
        if mode == "selftest":
            traceback.print_exc()
        print("Offline worker failed", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
