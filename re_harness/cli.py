"""Prometheus Forge operator commands for static reverse engineering."""

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import stat
import subprocess
import sys
import tempfile
import uuid

from . import accounts, decoding, evidence, local_model, policy, runtime, server
from .case import atomic_json, hashes

EXCERPTS = tuple(name for name in policy.TOOLS if name != "artifact_summary")
STATE = runtime.STATE
# Provenance labels stay plain: no scheme separators, credentials or URLs.
LABEL = r"[A-Za-z0-9][A-Za-z0-9 _./(),-]{0,159}"
MAX_CLAIM = 2000
MAX_EVIDENCE = 16
MAX_EVIDENCE_TEXT = 500
MAX_GRANTS = 128
FINDING_ID = r"F[0-9]{4,}"
# A closed case keeps these read-only operator commands. Everything else is refused by load_case.
CLOSED_READS = ("status", "verify", "export")


def emit(value):
    print(json.dumps(value, indent=2, ensure_ascii=True))


def bounded_text(limit, pattern=None):
    def parse(value):
        if len(value) > limit:
            raise argparse.ArgumentTypeError(f"must be at most {limit} characters")
        if pattern and not re.fullmatch(pattern, value):
            raise argparse.ArgumentTypeError("use a short sanitized label without credentials or URLs")
        return value
    return parse


def finding_id(value):
    if not re.fullmatch(FINDING_ID, value) or len(value) > 16:
        raise argparse.ArgumentTypeError("expected a finding ID such as F0001")
    return value


class AppendBounded(argparse.Action):
    def __call__(self, parser, namespace, values, option_string=None):
        items = list(getattr(namespace, self.dest, None) or [])
        if len(items) >= MAX_EVIDENCE:
            raise argparse.ArgumentError(self, f"accepts at most {MAX_EVIDENCE} entries")
        setattr(namespace, self.dest, items + [values])


def split_grants(record, now=None):
    now = now or dt.datetime.now(dt.timezone.utc)
    active, expired = [], []
    for grant in record["grants"]:
        (active if dt.datetime.fromisoformat(grant["expires_utc"]) > now else expired).append(grant)
    return active, expired


def provision(engine):
    STATE.mkdir(parents=True, exist_ok=True)
    runtime.require_build_space(engine)
    runtime.require_engine(engine)
    candidate = "static-re-harness:build-" + uuid.uuid4().hex
    with runtime.operator_lock(STATE):
        runtime.docker(engine, ["build", "--platform", "linux/amd64", "--file", "docker/Dockerfile",
                                "--tag", candidate, "."], check=True)
        image = runtime.identify_image(engine, candidate)
        record = runtime.publish_baseline(STATE, engine, image)
        runtime.docker(engine, ["image", "tag", image, runtime.TAG], check=True)
        runtime.docker(engine, ["image", "rm", candidate], stdout=subprocess.DEVNULL, check=True)
    emit(record)


def call_worker(record, args, **options):
    status, response = runtime.worker(record, args, **options)
    if status:
        raise runtime.RuntimeFailure("The offline Apprentice did not complete the operation")
    return response


def init_case(args):
    folder = runtime.case_path(STATE, args.case)
    with runtime.operator_lock(folder):
        scope_file = folder / "scope.json"
        if scope_file.exists():
            _, record = runtime.load_case(STATE, args.case, allow_pending=True)
        else:
            baseline = runtime.load_baseline(STATE)
            record = {**baseline, "case": args.case, "volume": "static-re-" + uuid.uuid4().hex,
                      "paused": False, "grants": [], "initialized": False}
            atomic_json(scope_file, record)
        if record["initialized"]:
            call_worker(record, ["case", "status"], cap=4 * 1024 * 1024)
            emit({"case": args.case, "status": "existing", "image": record["image"]})
            return
        runtime.docker(record["engine"], ["volume", "create", "--label", "io.static-re.role=evidence",
                       "--label", "io.static-re.case=" + args.case, record["volume"]],
                       stdout=subprocess.DEVNULL, check=True, timeout=20)
        code, result = runtime.worker(record, ["case", "status"], cap=4 * 1024 * 1024)
        if code != 0:
            call_worker(record, ["case", "init", "--title", args.title], writable=True, diagnostics=True)
        runtime.audit(folder, case=args.case, decision="case_initialized", image=record["image"])
        record["initialized"] = True
        atomic_json(scope_file, record)
    emit({"case": args.case, "volume": record["volume"], "image": record["image"]})


def action_options(args):
    values = {"artifact": args.artifact}
    for key in ("address", "offset", "limit"):
        value = getattr(args, key, None)
        if value is not None:
            values[key] = value
    return policy.validate(args.tool, values)


def change_scope(args):
    folder = runtime.case_path(STATE, args.case)
    with runtime.operator_lock(folder):
        _, record = runtime.load_case(STATE, args.case)
        event = {"case": args.case, "decision": args.command}
        if args.command == "grant":
            if record["paused"]:
                raise runtime.RuntimeFailure("Resume the case before granting excerpts")
            options = action_options(args)
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=args.minutes)
            active, expired = split_grants(record)
            grant = {"id": uuid.uuid4().hex, "tool": args.tool, "arguments": options, "audience": args.audience,
                     "expires_utc": expires.isoformat()}
            if len(active) >= MAX_GRANTS:
                raise runtime.RuntimeFailure("Too many active excerpt grants")
            record["grants"] = active + [grant]
            event.update(grant=grant, pruned=[item["id"] for item in expired])
        elif args.command == "revoke":
            retained = [grant for grant in record["grants"] if grant["id"] != args.grant]
            if len(retained) == len(record["grants"]):
                raise runtime.RuntimeFailure("Unknown grant ID")
            record["grants"] = retained
            event.update(grant=args.grant)
        else:
            record["paused"] = args.command == "pause"
        runtime.audit(folder, **event)
        atomic_json(folder / "scope.json", record)
    emit(event)


def list_cases(_args):
    rows = []
    root = STATE / "cases"
    for folder in sorted(root.iterdir()) if root.is_dir() else ():
        if not folder.is_dir() or not policy.match(folder.name, policy.CASE_ID):
            continue
        try:
            _, record = runtime.load_case(STATE, folder.name, allow_pending=True, allow_closed=True)
        except (OSError, ValueError, KeyError, RuntimeError):
            rows.append({"case": folder.name, "error": "Unreadable or invalid case scope record"})
            continue
        rows.append({"case": folder.name, "paused": record["paused"], "initialized": record["initialized"],
                     "closed": runtime.closed(record),
                     "image": record["image"], "yara_rules_sha256": record.get("yara_rules", {}).get("sha256")})
    emit({"cases": rows})


def list_grants(args):
    folder = runtime.case_path(STATE, args.case)
    with runtime.operator_lock(folder):
        _, record = runtime.load_case(STATE, args.case, allow_closed=True)
        active, expired = split_grants(record)
        if expired:
            record["grants"] = active
            runtime.audit(folder, case=args.case, decision="grants_pruned", pruned=[grant["id"] for grant in expired])
            atomic_json(folder / "scope.json", record)
    emit({"case": args.case, "paused": record["paused"], "grants": [
        {"id": grant["id"], "tool": grant["tool"], "artifact": grant["arguments"].get("artifact"),
         "selector": {key: value for key, value in grant["arguments"].items() if key != "artifact"},
         "audience": grant["audience"], "expires_utc": grant["expires_utc"]} for grant in active]})


def import_yara_rules(args):
    folder = runtime.case_path(STATE, args.case)
    with runtime.operator_lock(folder):
        _, record = runtime.load_case(STATE, args.case)
        runtime.audit(folder, case=args.case, decision="operator_requested", operation="yara-rules")
        with args.input.open("rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= policy.MAX_YARA_RULES:
                raise runtime.RuntimeFailure("YARA rules must be a regular file of at most 1 MiB")
            result = server.strict_json(call_worker(record, ["yara-rules"], source=stream, writable=True,
                                                    diagnostics=True))
        if (set(result) != {"sha256", "bytes", "rules"} or not policy.match(result["sha256"], policy.DIGEST) or
                type(result["bytes"]) is not int or type(result["rules"]) is not int):
            raise runtime.RuntimeFailure("Unexpected YARA import result")
        # Grants named matched bytes under the previous rules, so a new rule set retires them.
        retired = [grant["id"] for grant in record["grants"] if grant["tool"] == "yara_scan"]
        record["grants"] = [grant for grant in record["grants"] if grant["tool"] != "yara_scan"]
        record["yara_rules"] = {**result, "imported_utc": dt.datetime.now(dt.timezone.utc).isoformat()}
        event = {"case": args.case, "decision": "yara_rules_imported", "rules_sha256": result["sha256"],
                 "rules": result["rules"], "retired_grants": retired}
        runtime.audit(folder, **event)
        atomic_json(folder / "scope.json", record)
    emit(event)


def operator_options(args):
    opts = []
    sources = {"source": "--source", "parent": "--parent", "relation": "--relation",
               "completeness": "--completeness", "kind": "--kind", "confidence": "--confidence",
               "claim": "--claim", "supersedes": "--supersedes"}
    for field, flag in sources.items():
        value = getattr(args, field, None)
        if value is not None:
            opts.append(f"{flag}={value}")
    if args.command == "finding":
        opts += ["--artifact=" + value for value in args.artifact]
        opts += ["--evidence=" + value for value in args.evidence]
    return opts


def output_file(destination, writer):
    path = destination.resolve()
    if path.exists():
        raise runtime.RuntimeFailure("Output file already exists")
    fd, temporary = tempfile.mkstemp(prefix=".static-re-", dir=path.parent)
    temporary = Path(temporary)
    try:
        with os.fdopen(fd, "wb") as stream:
            writer(stream)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temporary, path)
    finally:
        temporary.unlink(missing_ok=True)
    return path


def result_digest(response):
    try:
        value = json.loads(response).get("sha256")
    except (ValueError, AttributeError):
        return {}
    return {"sha256": value} if policy.match(value, policy.DIGEST) else {}


def report_options(record):
    # The worker records the toolchain the report was produced under.
    opts = ["--image", record["image"]]
    if "yara_rules" in record:
        opts += ["--yara-rules-sha256", record["yara_rules"]["sha256"]]
    return opts


def run_operation(args, record, options):
    """Run one operator command in the worker and return its response and audited outcome."""
    if args.command == "ingest":
        if not all(value is None or policy.match(value, LABEL) for value in (args.source, args.relation)):
            raise runtime.RuntimeFailure("Use short sanitized source and relation labels without credentials or URLs")
        with args.input.open("rb") as stream:
            info = os.fstat(stream.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_size > policy.MAX_ARTIFACT:
                raise runtime.RuntimeFailure("Input must be a regular file no larger than 128 MiB")
            response = call_worker(record, ["ingest", *operator_options(args)], source=stream, writable=True,
                                   diagnostics=True)
        return response, result_digest(response)
    if args.command == "derive":
        if not policy.match(args.artifact, policy.DIGEST) or not (0 <= args.offset < policy.MAX_ARTIFACT and
                1 <= args.length <= decoding.INPUT_CAP):
            raise runtime.RuntimeFailure("Provide an ingested SHA-256 and a bounded byte range")
        response = call_worker(record, ["derive", args.artifact, args.method, str(args.offset), str(args.length)],
                               writable=True, diagnostics=True)
        return response, result_digest(response)
    if args.command == "export":
        if policy.match(args.item, policy.DIGEST) and args.output.suffix.lower() != ".bin":
            raise runtime.RuntimeFailure("Raw artifacts must use the inert .bin extension")
        path = output_file(args.output, lambda stream: call_worker(record, ["export", args.item], output=stream))
        return json.dumps({"exported": str(path)}).encode(), {}
    if args.command == "inspect":
        request = {"tool": args.tool, "arguments": options, "excerpt": True}
        if args.tool == "yara_scan":
            request["rules"] = runtime.yara_rules(record)
        mode = "capture" if args.full else "analyze"
        path = output_file(args.output, lambda stream: call_worker(
            record, [mode], request=json.dumps(request).encode("ascii"), output=stream,
            timeout=runtime.tool_timeout(args.tool)))
        digest = hashes(path)[1]["sha256"]
        return json.dumps({"exported": str(path), "sha256": digest}).encode(), {"output_sha256": digest}
    positionals = [args.artifact] if args.command == "triage" else []
    extra = report_options(record) if args.command == "report" else operator_options(args)
    writable = args.command in ("triage", "finding", "report")
    return call_worker(record, ["case", args.command, *positionals, *extra], writable=writable, diagnostics=True,
                       cap=4 * 1024 * 1024), {}


def operator_action(args):
    folder = runtime.case_path(STATE, args.case)
    if args.command == "finding":
        # The ledger lives in the evidence volume; evidence:<sha256> locators name host-side tool evidence.
        absent = evidence.missing(folder, args.evidence)
        if absent:
            raise runtime.RuntimeFailure("Unknown evidence id " + absent[0][:16] + "... in this case")
    with runtime.operator_lock(folder):
        _, record = runtime.load_case(STATE, args.case, allow_closed=args.command in CLOSED_READS)
        event = {"case": args.case, "operation": args.command}
        options = None
        if args.command == "inspect":
            options = action_options(args)
            event.update(tool=args.tool, artifact=options["artifact"], arguments=options)
        elif args.command == "export":
            event.update(item=args.item[:256])
        runtime.audit(folder, decision="operator_requested", **event)
        try:
            response, outcome = run_operation(args, record, options)
        except BaseException as error:
            # Exception text can carry worker or path detail, so the audit keeps a fixed reason.
            reason = "interrupted" if isinstance(error, KeyboardInterrupt) else "operation_failed"
            runtime.audit(folder, decision="operator_failed", reason=reason, **event)
            raise
        runtime.audit(folder, decision="operator_completed", **event, **outcome)
    print(response.decode("utf-8").strip())


def close_case(args):
    """Verify, report and irreversibly close a case. The evidence volume is retained."""
    folder = runtime.case_path(STATE, args.case)
    with runtime.operator_lock(folder):
        _, record = runtime.load_case(STATE, args.case)
        event = {"case": args.case, "operation": "close"}
        runtime.audit(folder, decision="operator_requested", **event)
        reason = "verify_failed"
        try:
            try:
                verified = server.strict_json(call_worker(record, ["case", "verify"], diagnostics=True,
                                                          cap=4 * 1024 * 1024))
            except (ValueError, runtime.RuntimeFailure) as error:
                raise runtime.RuntimeFailure("Ledger verification failed. The case stays open") from error
            if not isinstance(verified, dict) or verified.get("ok") is not True:
                raise runtime.RuntimeFailure("Ledger verification failed. The case stays open")
            reason = "report_failed"
            reported = server.strict_json(call_worker(record, ["case", "report", *report_options(record)],
                                                      writable=True, diagnostics=True, cap=4 * 1024 * 1024))
        except BaseException as error:
            reason = "interrupted" if isinstance(error, KeyboardInterrupt) else reason
            runtime.audit(folder, decision="operator_failed", reason=reason, **event)
            raise
        retired = [grant["id"] for grant in record["grants"]]
        record.update(grants=[], closed=True, closed_utc=dt.datetime.now(dt.timezone.utc).isoformat())
        outcome = {"retired_grants": retired, "closed_utc": record["closed_utc"]}
        for key in ("report_sha256", "case_sha256"):
            if isinstance(reported, dict) and policy.match(reported.get(key), policy.DIGEST):
                outcome[key] = reported[key]
        runtime.audit(folder, decision="case_closed", **event, **outcome)
        atomic_json(folder / "scope.json", record)
    emit({**event, "decision": "case_closed", **outcome})


def snapshot(args):
    record = runtime.load_baseline(STATE)
    runtime.identify_image(record["engine"], record["image"])
    if args.output:
        sidecar = args.output.resolve().with_suffix(args.output.suffix + ".json")
        if sidecar.exists():
            raise runtime.RuntimeFailure("Snapshot manifest already exists")
        archive = output_file(args.output, lambda stream: runtime.docker(record["engine"],
            ["image", "save", record["image"]], stdout=stream, check=True, timeout=900))
        record.update(archive_sha256=hashes(archive)[1]["sha256"])
        atomic_json(sidecar, record)
    emit(record)


def restore(args):
    sidecar = args.input.with_suffix(args.input.suffix + ".json")
    manifest = runtime.read_json(sidecar)
    runtime.validate_runtime(manifest)
    if hashes(args.input)[1]["sha256"] != manifest.get("archive_sha256"):
        raise runtime.RuntimeFailure("Snapshot archive SHA-256 mismatch")
    engine = args.engine or manifest["engine"]
    runtime.require_engine(engine)
    with runtime.operator_lock(STATE):
        with args.input.open("rb") as source:
            runtime.docker(engine, ["image", "load"], stdin=source, timeout=900, check=True)
        image = runtime.identify_image(engine, manifest["image"])
        record = runtime.publish_baseline(STATE, engine, image)
        runtime.docker(engine, ["image", "tag", image, runtime.TAG], check=True)
    emit(record)


def hookup(args):
    runtime.load_case(STATE, args.case)
    # Supply a launch recipe. Operator chooses the MCP client and its model and tools.
    command = sys.executable
    config = ["-m", "re_harness.cli", "serve", args.case]
    env = {"STATIC_RE_STATE_DIR": str(STATE)}
    if args.format == "codex":
        print("[mcp_servers.static_re]\ncommand = " + json.dumps(command) + "\nargs = " + json.dumps(config)
              + "\ncwd = " + json.dumps(str(runtime.ROOT)) + "\nenv = { STATIC_RE_STATE_DIR = "
              + json.dumps(env["STATIC_RE_STATE_DIR"]) + " }\nstartup_timeout_sec = 20\ntool_timeout_sec = 330"
                "\n")
    else:
        emit({"command": command, "args": config, "cwd": str(runtime.ROOT), "env": env, "tool_timeout_seconds": 330})


def forge_user(args):
    """Manage Forge sign-in accounts. New and reset accounts get a one-time setup code, never a password."""
    if args.action == "list":
        return emit(accounts.listing(STATE))
    if not args.user:
        raise ValueError("Name the account")
    known = {row["user"] for row in accounts.listing(STATE)}
    if args.action == "add" and args.user in known:
        raise ValueError("Account already exists. Use reset to issue a new setup code")
    if args.action in ("reset", "remove", "signout") and args.user not in known:
        raise ValueError("No such account")
    if args.action == "remove":
        accounts.remove(STATE, args.user)
        return emit({"user": args.user, "decision": "removed"})
    if args.action == "signout":
        accounts.end_sessions(STATE, args.user)
        return emit({"user": args.user, "decision": "sessions_ended"})
    if args.code_file and args.code_file.exists():
        raise ValueError("Setup code file already exists")
    code = accounts.issue_setup(STATE, args.user)
    result = {"user": args.user, "decision": "setup_issued", "expires_hours": accounts.SETUP_HOURS,
              "setup_page": "<prefix>setup"}
    if args.code_file:
        fd = os.open(args.code_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "w", encoding="ascii", newline="\n") as stream:
            stream.write(code + "\n")
        result["setup_code_file"] = str(args.code_file)
    else:
        result["setup_code"] = code
    emit(result)


def add_selector(parser):
    parser.add_argument("--address")
    parser.add_argument("--offset", type=int)
    parser.add_argument("--limit", type=int)


def make_parser():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    handlers = {}

    def command(name, handler, case_bound=True):
        child = sub.add_parser(name)
        handlers[name] = handler
        if case_bound:
            child.add_argument("case")
        return child

    command("provision", lambda a: provision(a.engine), False).add_argument("--engine", required=True)
    command("snapshot", snapshot, False).add_argument("--output", type=Path)
    restore_parser = command("restore", restore, False)
    restore_parser.add_argument("input", type=Path)
    restore_parser.add_argument("--engine")
    command("blank", lambda _: emit(json.loads(call_worker(runtime.load_baseline(STATE), ["blank"]))), False)
    command("init", init_case).add_argument("--title", required=True)
    ingest = command("ingest", operator_action)
    ingest.add_argument("input", type=Path)
    ingest.add_argument("--source", required=True, type=bounded_text(160, LABEL))
    ingest.add_argument("--parent")
    ingest.add_argument("--relation", type=bounded_text(160, LABEL))
    ingest.add_argument("--completeness", choices=("complete", "partial", "unknown"), default="unknown")
    derive = command("derive", operator_action)
    derive.add_argument("artifact")
    derive.add_argument("method", choices=decoding.FORMATS)
    derive.add_argument("offset", type=lambda value: int(value, 0))
    derive.add_argument("length", type=lambda value: int(value, 0))
    for name in ("status", "verify", "report"):
        command(name, operator_action)
    command("triage", operator_action).add_argument("artifact")
    finding = command("finding", operator_action)
    finding.add_argument("--artifact", action="append", required=True)
    finding.add_argument("--kind", choices=("observed", "inferred", "corroborated", "unknown"), required=True)
    finding.add_argument("--confidence", choices=("low", "medium", "high"), required=True)
    finding.add_argument("--claim", required=True, type=bounded_text(MAX_CLAIM))
    finding.add_argument("--evidence", action=AppendBounded, required=True, type=bounded_text(MAX_EVIDENCE_TEXT),
                         help=f"Evidence locator, repeatable up to {MAX_EVIDENCE} times")
    finding.add_argument("--supersedes", type=finding_id,
                         help="Current finding ID, such as F0001, that this finding replaces")
    rules = command("yara-rules", import_yara_rules)
    rules.add_argument("input", type=Path, help="Reviewed YARA rule source, at most 1 MiB, without includes")
    export = command("export", operator_action)
    export.add_argument("item")
    export.add_argument("output", type=Path)
    inspect = command("inspect", operator_action)
    inspect.add_argument("tool", choices=policy.TOOLS)
    inspect.add_argument("artifact")
    inspect.add_argument("--output", type=Path, required=True)
    inspect.add_argument("--full", action="store_true", help="Include the bounded raw evidence from the provider")
    add_selector(inspect)
    grant = command("grant", change_scope)
    grant.add_argument("tool", choices=EXCERPTS)
    grant.add_argument("artifact")
    grant.add_argument("--audience", choices=("local", "mcp"), default="local")
    grant.add_argument("--minutes", type=int, choices=range(1, 61), default=15, metavar="1..60")
    add_selector(grant)
    command("revoke", change_scope).add_argument("grant")
    command("grants", list_grants)
    command("cases", list_cases, False)
    command("close", close_case)
    for name in ("pause", "resume"):
        command(name, change_scope)
    users = command("forge-user", forge_user, False)
    users.add_argument("action", choices=("add", "reset", "remove", "signout", "list"))
    users.add_argument("user", nargs="?")
    users.add_argument("--code-file", type=Path,
                       help="Write the one-time setup code to this new file (mode 0600) instead of printing it")
    command("hookup", hookup).add_argument("--format", choices=("codex", "json"), default="codex")
    command("serve", lambda a: server.serve(STATE, a.case))
    model = command("ask", lambda a: print(local_model.chat(STATE, a.case, a.port, a.model, a.role, a.question)))
    model.add_argument("--model", required=True)
    model.add_argument("--role", choices=local_model.ROLES, default="native")
    model.add_argument("--port", type=int, default=11434)
    model.add_argument("question")
    return parser, handlers


def main():
    parser, handlers = make_parser()
    args = parser.parse_args()
    try:
        handlers[args.command](args)
    except (OSError, ValueError, KeyError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"Prometheus: {error}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
