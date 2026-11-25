"""Container entry point. All sample handling is byte-oriented and offline."""

import hashlib
import json
import os
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import traceback
from pathlib import Path

from . import case, decoding, policy, providers

ROOT = Path("/case")
FIXTURE = Path("/opt/fixtures/benign.elf")
YARA_RULES = ROOT / "rules" / "yara.yar"
SELFTEST_RULE = b'''import "elf"
rule prometheus_selftest : fixture { strings: $name = "example" condition: elf.type == elf.ET_DYN and $name }
'''
MAX_CASE_ARTIFACTS = 256
MAX_CASE_BYTES = 4 * 1024 * 1024 * 1024
MAX_SUMMARY_SECTIONS = 96
ELF_FIELDS = ("elf_class", "data_encoding", "machine", "e_type", "e_entry", "phnum", "shnum")


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
    # Numeric header fields only. Section, import and version names stay behind an excerpt grant.
    if "elf" in detail:
        info["elf"] = {key: detail["elf"][key] for key in ELF_FIELDS if key in detail["elf"]}
    if "macho" in detail and "cputype" in detail["macho"]:
        info["macho"] = {key: detail["macho"][key] for key in ("cputype", "filetype")}
    if "pe" in detail:
        pe = detail["pe"]
        info["pe"] = {"parsed": "sections" in pe, "sections_count": len(pe.get("sections", [])),
                      "import_libraries_count": len(pe.get("imports", {})),
                      "certificate_bytes": pe.get("certificate_size", 0)}
        if "sections" in pe:
            info["pe"].update({key: pe[key] for key in ("machine", "entry_rva", "image_base", "overlay_offset")})
            info["pe"]["sections"] = [
                {"rva": section["rva"], "raw_offset": section["offset"], "raw_size": section["raw_size"],
                 "virtual_size": section["virtual_size"], "flags": section["flags"],
                 "entropy": float(section["entropy"])}
                for section in pe["sections"][:MAX_SUMMARY_SECTIONS]]
    return info, None


def case_rules(digest):
    if not policy.match(digest, policy.DIGEST):
        raise ValueError("invalid_worker_request")
    if YARA_RULES.is_symlink() or not YARA_RULES.is_file():
        raise ValueError("yara_rules_missing")
    if hashlib.sha256(YARA_RULES.read_bytes()).hexdigest() != digest:
        raise ValueError("yara_rules_mismatch")
    return YARA_RULES


def analyze(request, full=False):
    expected = {"tool", "arguments", "excerpt"} | ({"rules"} if request.get("tool") == "yara_scan" else set())
    if set(request) != expected or type(request["excerpt"]) is not bool:
        raise ValueError("invalid_worker_request")
    name = request["tool"]
    options = policy.validate(name, request["arguments"])
    digest = options.pop("artifact")
    display_excerpt = request["excerpt"]
    if name in policy.EXCERPT_ONLY and not display_excerpt:
        raise ValueError("excerpt_grant_required")
    path, size, hashes = artifact(digest)
    if name == "artifact_imports":
        # The grant releases the names themselves, validated row by row on the host.
        summary, raw = providers.artifact_imports(path, options), None
    elif name.startswith("artifact_"):
        summary, raw = triage(name, path, digest, hashes, options)
    elif name == "yara_scan":
        summary, raw = providers.yara_scan(case_rules(request["rules"]), path, options)
        summary["rules_sha256"] = request["rules"]
    elif name == "capa_triage":
        summary, raw = providers.capa_triage(path, options)
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


def import_rules():
    source = sys.stdin.buffer.read(policy.MAX_YARA_RULES + 1)
    import yara

    try:
        rules = providers.yara_compile(source)
    except (yara.Error, UnicodeDecodeError, ValueError) as error:
        # The rule text is operator-supplied, so its compiler diagnostic is safe to show the operator.
        print(f"YARA rules rejected: {str(error)[:300]}", file=sys.stderr)
        raise ValueError("yara_rules_rejected") from error
    with case.locked(ROOT):
        case.read_case(ROOT)
        folder = YARA_RULES.parent
        if folder.is_symlink() or YARA_RULES.is_symlink():
            raise ValueError("yara_rules_path")
        folder.mkdir(exist_ok=True)
        fd, temporary = tempfile.mkstemp(prefix=".writing-", dir=folder)
        try:
            with os.fdopen(fd, "wb") as stream:
                stream.write(source)
                stream.flush()
                os.fsync(stream.fileno())
            os.replace(temporary, YARA_RULES)
        finally:
            Path(temporary).unlink(missing_ok=True)
    emit({"sha256": hashlib.sha256(source).hexdigest(), "bytes": len(source), "rules": len(list(rules))})


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


def synthetic_pe(section=b".idata", library=b"KERNEL32.dll", function=b"ExitProcess"):
    """A PE32 whose one section holds an import of one name and ordinal 7, for parser checks."""
    dos = b"MZ" + bytes(58) + struct.pack("<I", 0x40)
    coff = struct.pack("<HHIIIHH", 0x14C, 1, 0, 0, 0, 0xE0, 0x0102)
    directories = bytearray(16 * 8)
    directories[8:16] = struct.pack("<II", 0x1000, 40)
    optional = struct.pack("<HBBIIIIIIIIIHHHHHHIIIIHHIIIIII", 0x10B, 14, 0, 0, 0x200, 0, 0x1000, 0x1000, 0x1000,
                           0x400000, 0x1000, 0x200, 6, 0, 0, 0, 6, 0, 0, 0x2000, 0x200, 0, 2, 0,
                           0x100000, 0x1000, 0x100000, 0x1000, 0, 16) + bytes(directories)
    header = struct.pack("<8sIIIIIIHHI", section, 0x200, 0x1000, 0x200, 0x200, 0, 0, 0, 0, 0xC0000040)
    headers = dos + b"PE\x00\x00" + coff + optional + header
    thunks = struct.pack("<III", 0x1090, 0x80000007, 0)
    body = (struct.pack("<IIIII", 0x1040, 0, 0, 0x1080, 0x1060) + bytes(44) + thunks + bytes(20) + thunks
            + bytes(20) + library[:15].ljust(16, b"\x00") + b"\x00\x00" + function[:100] + b"\x00")
    return headers + bytes(0x200 - len(headers)) + body.ljust(0x200, b"\x00")


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
        with tempfile.NamedTemporaryFile(prefix="selftest-", suffix=".yar") as rules:
            rules.write(SELFTEST_RULE)
            rules.flush()
            yara_page, yara_detail = providers.yara_scan(rules.name, FIXTURE, {"offset": 0, "limit": 20})
        assert [row["rule"] for row in yara_page["rows"]] == ["prometheus_selftest"]
        assert yara_detail["matches"][0]["strings"][0]["matches"][0]["data_hex"] == b"example".hex()
        for forbidden in (b'import "console" rule a { condition: console.log("x") }', b'include "/etc/passwd"'):
            try:
                providers.yara_compile(forbidden)
            except Exception:
                continue
            raise AssertionError("YARA accepted a forbidden module or include")
        with tempfile.NamedTemporaryFile(prefix="selftest-", suffix=".bin") as sample:
            sample.write(synthetic_pe())
            sample.flush()
            pe_names = providers.artifact_imports(sample.name, {"offset": 0, "limit": 50})
        elf_names = providers.artifact_imports(FIXTURE, {"offset": 0, "limit": 50})
        assert pe_names["limitations"] == [] and [(row["kind"], row["name"], row["ordinal"]) for row in
                                                  pe_names["rows"]][2:] == [("pe_import", "ExitProcess", None),
                                                                            ("pe_import", "", 7)]
        assert elf_names["format"] == "elf" and not elf_names["limitations"]
        assert ("elf_needed", "libc.so.6") in [(row["kind"], row["name"]) for row in elf_names["rows"]]
        capa_page, _ = providers.capa_triage(FIXTURE, {"offset": 0, "limit": 50}, diagnostics=True)
        assert capa_page["format"] == "elf" and capa_page["rules_withheld"] == 0
        result.update(ghidra_mcp="function index, xrefs, decompilation", rea="native inspect and decompilation",
                      yara="operator rules with module allowlist", capa="pinned rules on fixture ELF",
                      imports="synthetic PE and fixture ELF names")
    emit(result)


def main():
    mode, *args = sys.argv[1:] or [""]
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
        elif mode == "yara-rules" and not args:
            import_rules()
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
