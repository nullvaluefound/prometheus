"""Drive a model through a disposable benchmark case and score its proposed findings against ground truth.

Needs the provisioned offline worker image and a configured Forge model. It creates a new case named bench-<hex>
in the state directory, admits the benign fixtures, asks their questions through the Forge chat path (the broker,
grants and audit apply as for any case), then scores the investigation store's proposals deterministically:

    python -m tests.benchmark.run --model <model-id> [--grant-imports] [--allow-cloud]

The case is left in place for inspection. Close it with the operator CLI when done.
"""

import argparse
import json
import sys
import tempfile
import uuid
from pathlib import Path

from re_harness import cli, investigation, local_model, models, runtime
from tests.benchmark import fixtures, score


def admit(record, data, label):
    with tempfile.TemporaryDirectory() as directory:
        path = Path(directory) / "fixture.bin"
        path.write_bytes(data)
        with path.open("rb") as stream:
            reply = json.loads(cli.call_worker(record, ["ingest", f"--source={label}", "--completeness=complete"],
                                               source=stream, writable=True, diagnostics=True))
    return reply["sha256"]


def run(model_id, grant_imports=False, allow_cloud=False, out=sys.stdout):
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
    for item in sets:
        if admit(record, item["bytes"], item["source"]) != item["sha256"]:
            raise SystemExit("A fixture was admitted under an unexpected SHA-256.")
        if grant_imports:
            cli.change_scope(argparse.Namespace(case=case_id, command="grant", tool="artifact_imports",
                                                artifact=item["sha256"], audience="mcp" if models.is_cloud(config)
                                                else "local", minutes=60, address=None, offset=0, limit=20))
    settings = {"role": "evidence", "tools": sorted(local_model.ROLES["evidence"]), "allow_cloud": allow_cloud}
    history = []
    for item in sets:
        for question in item["questions"]:
            row = investigation.add_question(state, case_id, question["text"], question["outcome"],
                                             question["artifacts"], "benchmark")
            prompt = (f"Work on question {row['id']}: {question['text']} Expected outcome: {question['outcome']}. "
                      f"The artifact is {question['artifacts'][0]}. Use your tools, record observations that cite "
                      "evidence ids, and propose findings with propose_finding.")
            try:
                history += [{"role": "user", "text": prompt}] + models.converse(
                    state, case_id, config, settings, history, prompt, "benchmark")
            except (models.ModelError, runtime.RuntimeFailure) as error:
                history.append({"role": "assistant", "text": "", "error": str(error)})
    candidates = investigation.load(state, case_id)["candidates"]
    truths = [truth for item in sets for truth in item["truths"]]
    report = {"case": case_id, "model": config["model"], "provider": config["provider"],
              "grant_imports": grant_imports, **score.score(candidates, truths),
              "turn_errors": sum(1 for row in history if row.get("error"))}
    print(json.dumps(report, indent=2), file=out)
    return report


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--model", required=True, help="A Forge model id from the Models page")
    parser.add_argument("--grant-imports", action="store_true",
                        help="Grant artifact_imports on each fixture so import-name truths are reachable")
    parser.add_argument("--allow-cloud", action="store_true")
    options = parser.parse_args(argv)
    run(options.model, options.grant_imports, options.allow_cloud)
    return 0


if __name__ == "__main__":
    sys.exit(main())
