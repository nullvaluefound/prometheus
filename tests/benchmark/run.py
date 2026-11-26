"""Drive a model through a disposable benchmark case and score its proposed findings against ground truth.

Needs the provisioned offline worker image and a configured Forge model. It creates a new case named bench-<hex>
in the state directory, admits the benign fixtures, asks their questions through the Forge chat path (the broker,
grants and audit apply as for any case), then scores the investigation store's proposals deterministically:

    python -m tests.benchmark.run --model <model-id> [--followups 2] [--grant-imports] [--allow-cloud]

By default the run plays the operator for grant requests: after each turn it approves every pending request on a
fixture, for exactly the call the model asked for, and gives the model a follow-up turn on the same question. That
measures the grant-request flow a real case uses. --followups 0 turns it off. --grant-imports also pre-grants
artifact_imports for the default page (offset 0, limit 20). The case is left in place for inspection; close it with
the operator CLI when done.
"""

import argparse
import json
import sys
import tempfile
import time
import uuid
from pathlib import Path

from re_harness import cli, grant_requests, investigation, local_model, models, runtime
from tests.benchmark import fixtures, score


def admit(record, data, label):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fixture.bin"
        path.write_bytes(data)
        with path.open("rb") as stream:
            reply = json.loads(cli.call_worker(record, ["ingest", f"--source={label}", "--completeness=complete"],
                                               source=stream, writable=True, diagnostics=True))
    return reply["sha256"]


def approve(state, case_id, digests, minutes=60):
    """Play the operator: grant every pending request on a fixture, for exactly the call it names."""
    approved = []
    for row in grant_requests.load(state, case_id):
        arguments = row["arguments"]
        if row["state"] != "pending" or arguments.get("artifact") not in digests:
            continue
        before = {grant["id"] for grant in runtime.load_case(state, case_id)[1]["grants"]}
        cli.change_scope(argparse.Namespace(case=case_id, command="grant", tool=row["tool"], audience=row["audience"],
                                            minutes=minutes, **{key: arguments.get(key) for key in
                                                                ("artifact", "address", "offset", "limit")}))
        issued = [grant["id"] for grant in runtime.load_case(state, case_id)[1]["grants"] if grant["id"] not in before]
        grant_requests.decide(state, case_id, row["id"], "approved", "benchmark", issued[-1] if issued else None)
        approved.append((row["tool"], arguments))
    return approved


def run(model_id, grant_imports=False, allow_cloud=False, followups=2, out=sys.stdout, record_nudge=True):
    state = runtime.STATE
    config = models.get(state, model_id)
    if models.is_cloud(config) and not allow_cloud:
        raise SystemExit("That is a cloud model. Pass --allow-cloud to send the benchmark case to it.")
    cli.STATE = state
    case_id = "bench-" + uuid.uuid4().hex[:8]
    cli.init_case(argparse.Namespace(case=case_id, title="Benchmark of benign fixtures"))
    _, record = runtime.load_case(state, case_id)
    baseline = runtime.load_baseline(state)
    sets = [fixtures.synthetic_pe(), fixtures.benign_elf(cli.call_worker(baseline, ["fixture"]))]
    audience = "mcp" if models.is_cloud(config) else "local"
    for item in sets:
        if admit(record, item["bytes"], item["source"]) != item["sha256"]:
            raise SystemExit("A fixture was admitted under an unexpected SHA-256.")
        if grant_imports:
            cli.change_scope(argparse.Namespace(case=case_id, command="grant", tool="artifact_imports",
                                                artifact=item["sha256"], audience=audience, minutes=60, address=None,
                                                offset=0, limit=20))
    digests = {item["sha256"] for item in sets}
    settings = {"role": "evidence", "tools": sorted(local_model.ROLES["evidence"]), "allow_cloud": allow_cloud}
    history, turns, started = [], 0, time.monotonic()
    for item in sets:
        for question in item["questions"]:
            row = investigation.add_question(state, case_id, question["text"], question["outcome"],
                                             question["artifacts"], "benchmark")
            prompt = (f"Work on question {row['id']}: {question['text']} Expected outcome: {question['outcome']}. "
                      f"The artifact is {question['artifacts'][0]}. Use your tools, record observations that cite "
                      "evidence ids, and propose findings with propose_finding.")
            for _ in range(followups + 1):
                try:
                    # The benchmark measures the lead-worker setup: a session asked once to record before it ends.
                    plan = models.Plan(purpose="benchmark", require_record=record_nudge)
                    history += [{"role": "user", "text": prompt}] + models.converse(
                        state, case_id, config, settings, history, prompt, "benchmark", plan=plan)
                except (models.ModelError, runtime.RuntimeFailure) as error:
                    history.append({"role": "assistant", "text": "", "error": str(error)})
                turns += 1
                approved = approve(state, case_id, digests) if followups else []
                if not approved:
                    break
                calls = "; ".join(f"{tool} {json.dumps(arguments, ensure_ascii=True)}" for tool, arguments in approved)
                prompt = (f"The operator approved your grant request for exactly this call: {calls}. Call it again with "
                          f"the same arguments, then finish question {row['id']} and propose findings.")
    candidates = investigation.load(state, case_id)["candidates"]
    truths = [truth for item in sets for truth in item["truths"]]
    report = {"case": case_id, "model": config["model"], "provider": config["provider"],
              "grant_imports": grant_imports, "followups": followups, "record_nudge": record_nudge, "turns": turns,
              "seconds": round(time.monotonic() - started), **score.score(candidates, truths),
              "turn_errors": sum(1 for row in history if row.get("error"))}
    print(json.dumps(report, indent=2), file=out)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", required=True, help="A Forge model id from the Models page")
    parser.add_argument("--followups", type=int, default=2, choices=range(0, 6), metavar="0..5",
                        help="Follow-up turns after approving the model's grant requests (0 approves nothing)")
    parser.add_argument("--grant-imports", action="store_true",
                        help="Also pre-grant artifact_imports on each fixture for offset 0, limit 20")
    parser.add_argument("--no-record-nudge", action="store_true",
                        help="Do not ask a session that recorded nothing to record before it ends")
    parser.add_argument("--allow-cloud", action="store_true")
    options = parser.parse_args(argv)
    run(options.model, options.grant_imports, options.allow_cloud, options.followups,
        record_nudge=not options.no_record_nudge)
    return 0


if __name__ == "__main__":
    sys.exit(main())
