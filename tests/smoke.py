"""Run the real Docker case path against a disposable benign fixture."""

import argparse
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import uuid
from unittest.mock import patch

from re_harness import case, cli, local_model, runtime, server


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
    assert initial["protocolVersion"] == "2025-11-25" and len(tools["tools"]) == 7
    assert not result["isError"], result


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
            doc = json.loads(cli.call_worker(record, ["case", "verify"]))
            assert doc["ok"] and doc["checked"] == 1
            cli.call_worker(record, ["case", "report"], writable=True)
            assert b"Benign verification fixture" in cli.call_worker(record, ["export", "report.md"])
            print("Verified blank workspace, case intake, stdio MCP, broker interception, Ghidra and evidence export.")
            if model:
                local_model.chat(state, case_id, port, model, "intake",
                                 f"Call artifact_summary for {digest}, then report the format and length.")
                events = [json.loads(line) for line in (state / "cases" / case_id / "audit.jsonl")
                          .read_text(encoding="ascii").splitlines()]
                assert any(event.get("audience") == "local" and event.get("tool") == "artifact_summary" and
                           event["decision"] == "completed" for event in events)
                print("Verified one completed, audited tool call from the local model.")
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
