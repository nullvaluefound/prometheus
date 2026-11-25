"""Run the real Docker case path against a disposable benign fixture."""

import argparse
import hashlib
import html
import http.client
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import uuid
from unittest.mock import patch
from urllib.parse import urlencode

from re_harness import case, cli, forge, local_model, runtime, server


def check_mcp(state, case_id, digest):
    requests = [
        {"method": "initialize", "params": {"protocolVersion": "2025-11-25"}},
        {"method": "tools/list"},
        {"method": "tools/call", "params": {"name": "artifact_summary", "arguments": {"artifact": digest}}},
    ]
    lines = "\n".join(json.dumps({"jsonrpc": "2.0", "id": number, **request})
                      for number, request in enumerate(requests, 1)) + "\n"
    env = {**os.environ, "STATIC_RE_STATE_DIR": str(state)}
    child = subprocess.run([sys.executable, "-m", "re_harness.cli", "serve", case_id], cwd=runtime.ROOT,
                           input=lines, text=True, capture_output=True, env=env, timeout=195, check=True)
    initial, tools, result = (json.loads(line)["result"] for line in child.stdout.splitlines())
    assert initial["protocolVersion"] == "2025-11-25" and len(tools["tools"]) == 10
    assert not result["isError"], result


def forge_request(path, method, route, headers, form=None):
    """Speak HTTP over the Forge's Unix socket the way the authenticating ingress would."""
    body = urlencode(form).encode("ascii") if form else b""
    lines = [f"{method} {route} HTTP/1.1", "Host: forge", "Connection: close"]
    lines += [f"{name}: {value}" for name, value in headers.items()]
    if form:
        lines.append(f"Content-Length: {len(body)}")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
        sock.settimeout(195)
        sock.connect(str(path))
        sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii") + body)
        response = http.client.HTTPResponse(sock)
        response.begin()
        return response.status, response.read().decode("utf-8"), dict(response.headers)


def check_forge(state, case_id, digest, broker):
    """Serve the Forge on a private socket: landing page, inspection, audited pause, then refusal."""
    if os.name != "posix" or not hasattr(socket, "AF_UNIX"):
        print("Skipped the Forge phase: the Forge serves only over a Unix socket on Linux.")
        return
    origin, prefix, operator = "https://forge.invalid", "/prometheus/", "smoke-operator"
    path = state / "forge.sock"
    get_headers = {"X-Forge-Operator": operator}
    post_headers = {**get_headers, "Origin": origin, "Content-Type": "application/x-www-form-urlencoded"}
    with forge.Forge(path, origin, prefix, state, {case_id}) as app:
        thread = threading.Thread(target=app.serve_forever, daemon=True)
        thread.start()
        try:
            status, body, _ = forge_request(path, "GET", prefix, get_headers)
            assert status == 200 and case_id in body and "Apprentices" in body, status
            assert digest not in body and "Artifact summary" not in body
            for label in ("Ghidra MCP", "REA", "YARA", "capa"):
                assert f"<li><span>{label}</span><span class=\"status\">Verified</span></li>" in body, label
            form = {"case": case_id, "artifact": digest}
            status, body, _ = forge_request(path, "POST", prefix + "inspect", post_headers, form)
            assert status == 200 and "<h2>Artifact summary</h2>" in body, (status, body[:200])
            assert html.escape('"format_hint": "ELF"', quote=True) in body
            status, _, headers = forge_request(path, "POST", prefix + "pause", post_headers, {"case": case_id})
            assert status == 303 and headers["Location"] == f"{prefix}cases/{case_id}", status
            events = [json.loads(line) for line in (state / "cases" / case_id / "audit.jsonl")
                      .read_text(encoding="ascii").splitlines()]
            assert any(event.get("decision") == "pause" and event.get("operator") == operator and
                       event.get("via") == "forge" for event in events)
            assert runtime.load_case(state, case_id)[1]["paused"]
            status, body, _ = forge_request(path, "POST", prefix + "inspect", post_headers, form)
            assert status == 400 and "Artifact summary" not in body, status
            assert broker.call({"name": "artifact_summary", "arguments": {"artifact": digest}})["isError"]
        finally:
            app.shutdown()
            thread.join(timeout=10)
    path.unlink(missing_ok=True)
    print("Verified the Forge landing page, a browser inspection, an audited browser pause and refusal after pause.")


def operator(state, *argv):
    parser, handlers = cli.make_parser()
    args = parser.parse_args(argv)
    with patch.object(cli, "STATE", state):
        handlers[args.command](args)


def check_imports(state, case_id, digest, broker):
    assert broker.call({"name": "artifact_imports", "arguments": {"artifact": digest}})["isError"]
    operator(state, "grant", case_id, "artifact_imports", digest, "--audience", "mcp", "--minutes", "5")
    imports = broker.call({"name": "artifact_imports", "arguments": {"artifact": digest}})
    assert not imports["isError"], imports
    rows = json.loads(imports["content"][0]["text"])["summary"]["rows"]
    assert any(row["kind"] == "elf_needed" and row["name"].startswith("libc.so") for row in rows), rows
    print("Verified import names are withheld until an operator grant releases them.")


def check_close(state, case_id, digest, broker):
    operator(state, "close", case_id)
    _, closed = runtime.load_case(state, case_id, allow_closed=True)
    assert closed["closed"] and not closed["grants"]
    assert json.loads(cli.call_worker(closed, ["case", "verify"]))["ok"]
    for argv in (("resume", case_id), ("grant", case_id, "artifact_strings", digest)):
        try:
            operator(state, *argv)
        except runtime.RuntimeFailure as error:
            assert "closed" in str(error)
        else:
            raise AssertionError(argv)
    assert broker.call({"name": "artifact_summary", "arguments": {"artifact": digest}})["isError"]
    print("Verified an irreversible close that keeps verify and refuses changes.")


def execute(model=None, port=11434):
    baseline = runtime.load_baseline(runtime.STATE)
    case_id = "smoke-" + uuid.uuid4().hex[:12]
    with tempfile.TemporaryDirectory() as temp:
        state = Path(temp) / "StaticREHarness"
        state.mkdir()
        case.atomic_json(state / "baseline.json", baseline)
        try:
            probe = json.loads(cli.call_worker(baseline, ["blank"]))
            assert probe["blank"] and probe["offline"]
            with patch.object(cli, "STATE", state):
                cli.init_case(argparse.Namespace(case=case_id, title="Benign verification fixture"))
            _, record = runtime.load_case(state, case_id)
            fixture = cli.call_worker(baseline, ["fixture"])
            digest = hashlib.sha256(fixture).hexdigest()
            artifact = state / "input.bin"
            artifact.write_bytes(fixture)
            with artifact.open("rb") as source:
                admitted = json.loads(cli.call_worker(record, ["ingest", "--source", "Built-in fixture"],
                                                     source=source, writable=True))
            assert admitted["sha256"] == digest
            broker = server.Broker(state, case_id)
            result = broker.call({"name": "artifact_summary", "arguments": {"artifact": digest}})
            assert not result["isError"], result
            assert json.loads(result["content"][0]["text"])["summary"]["format_hint"] == "ELF"
            check_mcp(state, case_id, digest)
            denied = broker.call({"name": "run_ghidra_script", "arguments": {"artifact": digest}})
            assert denied["isError"]
            functions = broker.call({"name": "ghidra_functions", "arguments": {"artifact": digest}})
            assert not functions["isError"], functions
            assert json.loads(functions["content"][0]["text"])["summary"]["rows"]
            capa = broker.call({"name": "capa_triage", "arguments": {"artifact": digest}})
            assert not capa["isError"], capa
            assert json.loads(capa["content"][0]["text"])["summary"]["format"] == "elf"
            assert broker.call({"name": "yara_scan", "arguments": {"artifact": digest}})["isError"]
            rules = state / "rules.yar"
            rules.write_text('rule smoke_example { strings: $a = "example" condition: $a }\n', encoding="ascii", newline="\n")
            with patch.object(cli, "STATE", state):
                cli.import_yara_rules(argparse.Namespace(case=case_id, input=rules))
            yara = broker.call({"name": "yara_scan", "arguments": {"artifact": digest}})
            assert not yara["isError"], yara
            assert [row["rule"] for row in json.loads(yara["content"][0]["text"])["summary"]["rows"]] == ["smoke_example"]
            doc = json.loads(cli.call_worker(record, ["case", "verify"]))
            assert doc["ok"] and doc["checked"] == 1
            _, current = runtime.load_case(state, case_id)
            cli.call_worker(current, ["case", "report", *cli.report_options(current)], writable=True)
            report = cli.call_worker(current, ["export", "report.md"])
            assert b"Benign verification fixture" in report and current["image"].encode() in report
            assert current["yara_rules"]["sha256"].encode() in report
            print("Verified blank workspace, case intake, stdio MCP, broker interception, Ghidra, capa, YARA and evidence export.")
            if model:
                local_model.chat(state, case_id, port, model, "intake",
                                 f"Call artifact_summary for {digest}, then report the format and length.")
                events = [json.loads(line) for line in (state / "cases" / case_id / "audit.jsonl")
                          .read_text(encoding="ascii").splitlines()]
                assert any(event.get("audience") == "local" and event.get("tool") == "artifact_summary" and
                           event["decision"] == "completed" for event in events)
                print("Verified one completed, audited tool call from the local model.")
            check_imports(state, case_id, digest, broker)
            check_forge(state, case_id, digest, broker)
            check_close(state, case_id, digest, broker)
        finally:
            scope = runtime.case_path(state, case_id) / "scope.json"
            if scope.exists():
                record = runtime.read_json(scope)
                runtime.volume_exists(record)
                runtime.docker(record["engine"], ["volume", "rm", record["volume"]], stdout=subprocess.DEVNULL,
                               check=True, timeout=20)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model")
    parser.add_argument("--port", type=int, default=11434)
    args = parser.parse_args()
    execute(args.model, args.port)
