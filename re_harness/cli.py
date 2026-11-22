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

from . import decoding, local_model, policy, runtime, server
from .case import atomic_json, hashes

EXCERPTS = tuple(name for name in policy.TOOLS if name != "artifact_summary")
STATE = runtime.STATE


def emit(value):
    print(json.dumps(value, indent=2, ensure_ascii=True))


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
            options = action_options(args)
            expires = dt.datetime.now(dt.timezone.utc) + dt.timedelta(minutes=args.minutes)
            active = [grant for grant in record["grants"] if dt.datetime.fromisoformat(grant["expires_utc"]) >
                      dt.datetime.now(dt.timezone.utc)]
            grant = {"id": uuid.uuid4().hex, "tool": args.tool, "arguments": options, "audience": args.audience,
                     "expires_utc": expires.isoformat()}
            if len(active) >= 128:
                raise runtime.RuntimeFailure("Too many active excerpt grants")
            record["grants"] = active + [grant]
            event.update(grant=grant)
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


def operator_options(args):
    opts = []
    sources = {"source": "--source", "parent": "--parent", "relation": "--relation",
               "completeness": "--completeness", "kind": "--kind", "confidence": "--confidence",
               "claim": "--claim"}
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


def operator_action(args):
    folder = runtime.case_path(STATE, args.case)
    with runtime.operator_lock(folder):
        _, record = runtime.load_case(STATE, args.case)
        runtime.audit(folder, case=args.case, decision="operator_requested", operation=args.command)
        if args.command == "ingest":
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9 _./(),-]{0,159}", args.source):
                raise runtime.RuntimeFailure("Use a short sanitized source label without credentials or URLs")
            with args.input.open("rb") as stream:
                info = os.fstat(stream.fileno())
                if not stat.S_ISREG(info.st_mode) or info.st_size > policy.MAX_ARTIFACT:
                    raise runtime.RuntimeFailure("Input must be a regular file no larger than 128 MiB")
                response = call_worker(record, ["ingest", *operator_options(args)], source=stream, writable=True,
                                       diagnostics=True)
        elif args.command == "derive":
            if not policy.match(args.artifact, policy.DIGEST) or not (0 <= args.offset < policy.MAX_ARTIFACT and
                    1 <= args.length <= decoding.INPUT_CAP):
                raise runtime.RuntimeFailure("Provide an ingested SHA-256 and a bounded byte range")
            response = call_worker(record, ["derive", args.artifact, args.method, str(args.offset), str(args.length)],
                                   writable=True, diagnostics=True)
        elif args.command == "export":
            if policy.match(args.item, policy.DIGEST) and args.output.suffix.lower() != ".bin":
                raise runtime.RuntimeFailure("Raw artifacts must use the inert .bin extension")
            path = output_file(args.output, lambda stream: call_worker(record, ["export", args.item], output=stream))
            response = json.dumps({"exported": str(path)}).encode()
        elif args.command == "inspect":
            request = {"tool": args.tool, "arguments": action_options(args), "excerpt": True}
            mode = "capture" if args.full else "analyze"
            path = output_file(args.output, lambda stream: call_worker(
                record, [mode], request=json.dumps(request).encode("ascii"), output=stream))
            response = json.dumps({"exported": str(path), "sha256": hashes(path)[1]["sha256"]}).encode()
        else:
            positionals = [args.artifact] if args.command == "triage" else []
            writable = args.command in ("triage", "finding", "report")
            response = call_worker(record, ["case", args.command, *positionals, *operator_options(args)],
                                   writable=writable, diagnostics=True, cap=4 * 1024 * 1024)
        runtime.audit(folder, case=args.case, decision="operator_completed", operation=args.command)
    print(response.decode("utf-8").strip())


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
              + json.dumps(env["STATIC_RE_STATE_DIR"]) + " }\nstartup_timeout_sec = 20\ntool_timeout_sec = 185"
                "\n")
    else:
        emit({"command": command, "args": config, "cwd": str(runtime.ROOT), "env": env, "tool_timeout_seconds": 185})


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
    ingest.add_argument("--source", required=True)
    ingest.add_argument("--parent")
    ingest.add_argument("--relation")
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
    finding.add_argument("--claim", required=True)
    finding.add_argument("--evidence", action="append", required=True)
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
    for name in ("pause", "resume"):
        command(name, change_scope)
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
