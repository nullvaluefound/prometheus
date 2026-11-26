"""Investigation runs: lifecycle, completion by check then operator, budgets and settling, stopping and restarts."""

import json
import os
from pathlib import Path
import re
import tempfile
import unittest
from unittest.mock import patch

from re_harness import forge, investigate, investigation, models, runtime, server
from re_harness.case import atomic_json
from tests.forge_support import ForgeServer, ScriptedAdapter, write_case

DIGEST = "a" * 64
SUMMARY = {"tool": "artifact_summary", "artifact": DIGEST, "artifact_bytes": 16,
           "summary": {"size": 16, "format_hint": "ELF", "strings_count": 0, "strings_truncated": False,
                       "entry": "0x401000"}}
CONFIG = {"provider": "ollama", "base_url": "http://127.0.0.1:11434", "model": "lab"}
SETTINGS = {"model": "lab", "allow_cloud": False, "role": "evidence",
            "tools": sorted(models.local_model.ROLES["evidence"])}


def call(name, **arguments):
    return {"id": None, "name": name, "arguments": arguments}


def last_results(adapter):
    return [texts for kind, texts in adapter.seen if kind == "results"][-1]


def evidence_id(adapter):
    return re.search(r'"evidence_id": "([0-9a-f]{64})"', last_results(adapter)[0])[1]


class RunTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        write_case(self.state, "review", "sha256:" + DIGEST)
        self.folder = runtime.case_path(self.state, "review")
        for patcher in (patch.object(runtime, "worker", return_value=(0, json.dumps(SUMMARY).encode())),
                        patch.object(server.projection, "project", side_effect=lambda value, *args: value),
                        patch.object(forge, "case_ledger", return_value={"artifacts": {DIGEST: {}}, "findings": []}),
                        patch.dict(models.ADAPTERS, {"ollama": ScriptedAdapter})):
            patcher.start()
            self.addCleanup(patcher.stop)

    def question(self, artifacts=(DIGEST,)):
        return investigation.add_question(self.state, "review", "Is it an ELF?", "Its format from a tool result",
                                          list(artifacts), "analyst")["id"]

    def start(self, **budgets):
        return investigate.start(self.state, "review", "analyst", {DIGEST}, budgets or None)

    def step(self, *script):
        ScriptedAdapter.script = list(script)
        return investigate.step(self.state, "review", CONFIG, SETTINGS, "analyst")

    def run_state(self):
        return investigate.current(self.state, "review")

    def data(self):
        return investigation.load(self.state, "review")

    def test_a_run_needs_a_usable_question(self):
        with self.assertRaisesRegex(investigation.InvestigationError, "no_usable_question"):
            self.start()
        self.question(artifacts=["b" * 64])
        with self.assertRaisesRegex(investigation.InvestigationError, "no_usable_question"):
            self.start()
        self.question()
        run = self.start()
        self.assertEqual((run["id"], run["state"], run["questions"]), ("R1", "queued", ["Q2"]))
        with self.assertRaisesRegex(investigation.InvestigationError, "investigation_active"):
            self.start()

    def test_a_run_goes_from_plan_to_lead_to_review_to_an_answer_the_operator_closes(self):
        question = self.question()
        self.start()
        planned = self.step(("", [call("add_lead", artifact=DIGEST, title="Check the header")]), ("Planned.", []))
        self.assertEqual((planned["did"], planned["state"], planned["next"]), ("planned", "running", True))
        planner = ScriptedAdapter.last
        self.assertIn("Investigation planner", planner.system)
        self.assertNotIn("artifact_summary", [name for name, _, _ in planner.tools])

        def propose(adapter):
            return "", [call("propose_finding", claim=f"{DIGEST} is an ELF entering at 0x401000.", kind="observed",
                             confidence="medium", artifacts=[DIGEST], evidence=[evidence_id(adapter)])]
        worked = self.step(("", [call("artifact_summary", artifact=DIGEST)]), propose, ("Wrap-up: an ELF.", []))
        self.assertEqual(worked["did"], "lead L1")
        lead = self.data()["leads"][0]
        self.assertEqual((lead["state"], lead["summary"]["text"], lead["summary"]["audience"]),
                         ("done", "Wrap-up: an ELF.", "local"))
        self.assertEqual(self.data()["candidates"][0]["check"]["result"], "passed")
        reviewed = self.step(("", [call("submit_verdict", verdict="supported", rationale="The header says ELF.")]))
        self.assertEqual(reviewed["did"], "reviewed C1")
        answered = self.step(("", [call("propose_answer", question=question, candidates=["C1"]),
                                   call("state_need", need=f"Close {question} if C1 answers it.")]), ("Done.", []))
        self.assertEqual((answered["state"], answered["next"]), ("waiting", False))
        run = self.run_state()
        self.assertEqual(run["need"]["text"], f"Close {question} if C1 answers it.")
        self.assertEqual(self.data()["questions"][0]["state"], "answer_proposed")
        self.assertGreater(run["spent"]["calls"], 0)
        # No model output ends the run. The operator closing the question does.
        self.assertEqual(self.step()["did"], "nothing")
        investigation.set_question_state(self.state, "review", question, "closed", "analyst")
        self.assertEqual(investigate.check_answered(self.state, "review", "analyst")["state"], "answered")
        states = [row["to"] for row in self.run_state()["history"]]
        self.assertEqual(states, ["queued", "running", "waiting", "answered"])
        audited = [json.loads(line) for line in (self.folder / "audit.jsonl").read_text().splitlines()]
        self.assertEqual([event["outcome"] for event in audited if event["decision"] == "investigation_transition"],
                         states)

    def test_answers_need_passed_checks_and_the_question_s_artifacts(self):
        question = self.question()
        self.start()

        def change(data):
            reviewed = [{"verdict": "insufficient"}]  # already reviewed, so the step plans instead
            data["candidates"] += [
                {"id": "C1", "state": "proposed", "check": {"result": "failed"}, "artifacts": [DIGEST],
                 "verdicts": reviewed},
                {"id": "C2", "state": "proposed", "check": {"result": "passed"}, "artifacts": ["b" * 64],
                 "verdicts": reviewed},
                {"id": "C3", "state": "proposed", "check": {"result": "not_assessed"}, "artifacts": [DIGEST],
                 "verdicts": reviewed}]
        investigation.update(self.state, "review", change)
        self.step(("", [call("propose_answer", question=question, candidates=[candidate])
                        for candidate in ("C1", "C2", "C3")] + [call("propose_answer", question="Q9",
                                                                     candidates=["C1"])]), ("", []))
        reasons = [json.loads(text)["reason"] for text in last_results(ScriptedAdapter.last)]
        self.assertEqual(reasons, ["candidate_check_not_passed", "candidate_not_for_question",
                                   "candidate_check_not_passed", "question_not_in_run"])
        self.assertEqual(self.data()["questions"][0]["state"], "open")

    def test_a_spent_budget_settles_with_a_tool_free_summary(self):
        self.question()
        run = self.start(calls=8)
        self.step(("", [call("add_lead", artifact=DIGEST, title="x")]), ("", []))
        investigate.change_run(self.state, "review", run["id"], lambda value, _: value["spent"].update(calls=8))
        settled = self.step(("Q1 is open; L1 is open; a grant would help.", [call("add_lead", artifact=DIGEST,
                                                                                    title="ignored")]))
        self.assertEqual((settled["did"], settled["state"]), ("settled", "exhausted"))
        self.assertEqual(ScriptedAdapter.last.tools, [])
        self.assertEqual(ScriptedAdapter.last.finals, [True])
        self.assertEqual(self.run_state()["summary"]["text"], "Q1 is open; L1 is open; a grant would help.")
        self.assertEqual(len(self.data()["leads"]), 1)  # the settle turn added nothing

    def test_a_cancel_stops_the_lead_at_its_next_broker_call(self):
        self.question()
        run = self.start()
        self.step(("", [call("add_lead", artifact=DIGEST, title="x")]), ("", []))

        def cancel(adapter):
            investigate.operator_action(self.state, "review", "cancel", "analyst")
            return "", [call("artifact_summary", artifact=DIGEST)]
        result = self.step(("", [call("artifact_summary", artifact=DIGEST)]), cancel, ("Stopped early.", []))
        self.assertEqual((result["state"], result["next"]), ("cancelled", False))
        self.assertEqual(json.loads(last_results(ScriptedAdapter.last)[0])["reason"], "investigation_stopped")
        lead = self.data()["leads"][0]
        self.assertEqual((lead["state"], lead["summary"]["text"]), ("stopped", "Stopped early."))
        self.assertEqual(runtime.worker.call_count, 1)

    def test_a_restart_pauses_live_runs_and_reopens_claimed_leads(self):
        self.question()
        run = self.start()
        investigate.transition(self.state, "review", run["id"], "running", "forge")

        def claim(data):
            data["leads"].append({"id": "L1", "state": "claimed", "artifact": DIGEST, "title": "x"})
        investigation.update(self.state, "review", claim)
        investigate.recover(self.state, ["review"])
        self.assertEqual(self.run_state()["state"], "paused")
        self.assertEqual(self.data()["leads"][0]["state"], "open")
        self.assertEqual(self.step()["did"], "nothing")
        investigate.operator_action(self.state, "review", "resume", "analyst")
        self.assertEqual(self.run_state()["state"], "running")

    def test_active_time_stops_counting_while_paused(self):
        self.question()
        run = self.start()
        with patch.object(investigate.time, "time", side_effect=[1000.0, 1100.0]):
            investigate.transition(self.state, "review", run["id"], "running", "forge")
            investigate.transition(self.state, "review", run["id"], "paused", "analyst")
        self.assertEqual(self.run_state()["spent"]["active_seconds"], 100.0)
        self.assertIsNone(self.run_state()["active_since"])

    def test_a_paused_case_pauses_its_run(self):
        self.question()
        self.start()
        atomic_json(self.folder / "scope.json", {**runtime.read_json(self.folder / "scope.json"), "paused": True})
        self.assertEqual(self.step()["state"], "paused")


class RunReviewFixTests(RunTests):
    """The runner review's findings: mid-step pauses, stuck leads, in-session budgets, audited planner tools."""

    def lead_ready(self, **budgets):
        self.question()
        run = self.start(**budgets)
        self.step(("", [call("add_lead", artifact=DIGEST, title="x")]), ("", []))
        return run

    def test_pausing_the_case_mid_lead_pauses_the_run(self):
        self.lead_ready()

        def pause(adapter):
            atomic_json(self.folder / "scope.json", {**runtime.read_json(self.folder / "scope.json"), "paused": True})
            return "", [call("artifact_summary", artifact=DIGEST)]
        result = self.step(("", [call("artifact_summary", artifact=DIGEST)]), pause, ("", []))
        self.assertEqual((result["state"], result["next"]), ("paused", False))
        self.assertEqual(self.data()["leads"][0]["state"], "open")
        investigate.operator_action(self.state, "review", "resume", "analyst")
        self.assertEqual(self.run_state()["state"], "running")

    def test_a_lead_never_stays_claimed_when_its_run_is_replaced(self):
        self.lead_ready()

        def replace(adapter):
            investigate.operator_action(self.state, "review", "cancel", "analyst")
            investigate.start(self.state, "review", "analyst", {DIGEST})
            return "", [call("artifact_summary", artifact=DIGEST)]
        self.step(("", [call("artifact_summary", artifact=DIGEST)]), replace, ("Partial wrap-up.", []))
        lead = self.data()["leads"][0]
        self.assertEqual((lead["state"], lead["summary"]["text"], lead["summary"]["run"]),
                         ("stopped", "Partial wrap-up.", "R1"))
        self.assertEqual(self.run_state()["id"], "R2")

    def test_recovery_reopens_claimed_leads_of_paused_runs_and_skips_downtime(self):
        run = self.lead_ready()

        def crash(data):
            data["leads"][0]["state"] = "claimed"
            data["run"]["current_lead"] = "L1"
            data["run"]["active_since"] = 1000.0
            data["run"]["spent"]["active_seconds"] = 0.0
            data["run"]["updated_utc"] = "1970-01-01T00:18:20+00:00"  # 1100 seconds
        investigation.update(self.state, "review", crash)
        investigate.recover(self.state, ["review"])
        run = self.run_state()
        self.assertEqual((run["state"], run["current_lead"], run["active_since"]), ("paused", None, None))
        self.assertEqual(run["spent"]["active_seconds"], 100.0)
        self.assertEqual(self.data()["leads"][0]["state"], "open")
        investigate.operator_action(self.state, "review", "resume", "analyst")
        investigate.operator_action(self.state, "review", "pause", "analyst")

        def claim(data):
            data["leads"][0]["state"] = "claimed"
        investigation.update(self.state, "review", claim)
        investigate.recover(self.state, ["review"])
        self.assertEqual(self.data()["leads"][0]["state"], "open")

    def test_a_session_stops_when_its_own_calls_spend_the_budget(self):
        self.lead_ready(calls=8)
        spent = self.run_state()["spent"]["calls"]  # the planner round's calls count too
        runtime.worker.reset_mock()
        many = ("", [call("artifact_summary", artifact=DIGEST)] * 4)
        self.step(many, many, ("Wrapped.", []))  # the eighth call is refused, then the wrap-up step
        # Without the live check this session would make 12 worker calls.
        self.assertEqual(runtime.worker.call_count, 8 - spent)
        self.assertEqual(self.run_state()["spent"]["calls"], 8)
        lead = self.data()["leads"][0]
        self.assertEqual((lead["state"], lead["summary"]["text"]), ("stopped", "Wrapped."))

    def test_planner_tools_are_audited_and_refused_once_the_run_stops(self):
        question = self.question()
        self.start()

        def cancel_then_write(adapter):
            investigate.operator_action(self.state, "review", "cancel", "analyst")
            return "", [call("propose_answer", question=question, candidates=["C1"]),
                        call("state_need", need="Anything."), call("retire_lead", lead="L1")]
        self.step(cancel_then_write, ("", []))
        reasons = [json.loads(text)["reason"] for text in last_results(ScriptedAdapter.last)]
        self.assertEqual(reasons, ["investigation_stopped"] * 3)
        self.assertEqual(self.data()["questions"][0]["state"], "open")
        self.assertIsNone(self.run_state()["need"])

    def test_planner_writes_are_audited_with_ids_only(self):
        question = self.question()
        self.start()
        self.step(("", [call("state_need", need="Grant the decoder at 0x401000, please.")]), ("", []))
        events = [json.loads(line) for line in (self.folder / "audit.jsonl").read_text().splitlines()
                  if '"state_need"' in line]
        self.assertEqual([event["decision"] for event in events], ["dispatched", "investigation_write"])
        self.assertNotIn("decoder", json.dumps(events))
        self.assertIn("text_sha256", events[0]["arguments"])

    def test_lead_workers_get_only_the_case_s_allowed_tools(self):
        self.lead_ready()
        ScriptedAdapter.script = [("Done.", [])]
        investigate.step(self.state, "review", CONFIG, {**SETTINGS, "tools": ["artifact_summary"]}, "analyst")
        offered = {name for name, _, _ in ScriptedAdapter.last.tools}
        self.assertIn("artifact_summary", offered)
        self.assertFalse(offered & {"ghidra_functions", "artifact_strings", "propose_finding", "note_grant_need"})


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class RunApiTests(ForgeServer, unittest.TestCase):
    def setUp(self):
        self.start_forge()
        for patcher in (patch.object(forge, "case_ledger", return_value={"artifacts": {self.digest: {}}, "findings": []}),
                        patch.dict(models.ADAPTERS, {"ollama": ScriptedAdapter})):
            patcher.start()
            self.addCleanup(patcher.stop)
        self.api("POST", "models", {"id": "lab", "name": "Lab", "provider": "ollama",
                                    "base_url": "http://127.0.0.1:11434", "model": "qwen3:32b"})
        self.api("PUT", "cases/review/settings", {"model": "lab", "allow_cloud": False, "role": "evidence",
                                                 "tools": ["artifact_summary"]})

    def wait_for_steps(self):
        """Wait until no investigation step is queued or running, including steps chained after the first."""
        for _ in range(200):
            live = [task for task in self.api("GET", "tasks?case=review")[1]["tasks"]
                    if task["kind"] == "investigate" and task["state"] in ("queued", "running")]
            if not live:
                return
            self.wait(live[0])
        raise AssertionError("investigation steps did not settle")

    def test_the_operator_starts_steers_and_ends_a_run(self):
        self.assertEqual(self.api("POST", "cases/review/investigation/start", {})[1]["error"], "no_usable_question")
        self.api("POST", "cases/review/questions", {"text": "Is it an ELF?", "outcome": "Its format",
                                                    "artifacts": [self.digest]})
        self.assertEqual(self.api("POST", "cases/review/investigation/start", {"budgets": {"calls": 1}})[0], 400)
        ScriptedAdapter.script = [("Nothing to plan.", [])]
        status, run = self.api("POST", "cases/review/investigation/start", {"budgets": {"minutes": 30}})
        self.assertEqual((status, run["state"], run["budgets"]["minutes"]), (200, "queued", 30))
        self.wait_for_steps()
        run = self.api("GET", "cases/review/investigation")[1]["run"]
        self.assertEqual((run["state"], run["need"]["text"]), ("waiting", investigate.NEED_DEFAULT))
        waiting = self.api("GET", "overview")[1]["waiting"]["items"]
        self.assertIn(("investigation_waiting", "R1"), [(item["kind"], item["id"]) for item in waiting])
        self.assertEqual(self.api("POST", "cases/review/investigation/message", {"text": "Look at 0x401000."})[1]
                         ["message"]["text"], "Look at 0x401000.")
        self.assertEqual(self.api("POST", "cases/review/investigation/fly", {})[0], 404)
        ScriptedAdapter.script = [("Still nothing.", [])]
        self.assertEqual(self.api("POST", "cases/review/investigation/resume", {})[1]["state"], "running")
        self.wait_for_steps()
        self.assertEqual(self.api("POST", "cases/review/investigation/cancel", {})[1]["state"], "cancelled")
        self.assertEqual(self.api("POST", "cases/review/investigation/pause", {})[1]["error"], "invalid_transition")
        self.assertTrue(self.api("POST", "cases/review/investigation/acknowledge", {})[1]["acknowledged"])
        status, question = self.api("POST", "cases/review/questions/Q1/state", {"state": "closed"})
        self.assertEqual(status, 200)

    def test_closing_the_last_question_answers_a_waiting_run(self):
        self.api("POST", "cases/review/questions", {"text": "Is it an ELF?", "outcome": "Its format",
                                                    "artifacts": [self.digest]})
        ScriptedAdapter.script = [("Nothing to plan.", [])]
        self.api("POST", "cases/review/investigation/start", {})
        self.wait_for_steps()
        self.assertEqual(self.api("GET", "cases/review/investigation")[1]["run"]["state"], "waiting")
        self.api("POST", "cases/review/questions/Q1/state", {"state": "closed"})
        self.assertEqual(self.api("GET", "cases/review/investigation")[1]["run"]["state"], "answered")

    def test_dropping_a_queued_step_pauses_its_run(self):
        self.api("POST", "cases/review/questions", {"text": "Is it an ELF?", "outcome": "Its format",
                                                    "artifacts": [self.digest]})
        release = __import__("threading").Event()
        blocker = self.app.tasks.submit("report", "review", "slow", "analyst", lambda: release.wait(5) and {})
        self.api("POST", "cases/review/investigation/start", {})
        queued = next(task for task in self.api("GET", "tasks?case=review")[1]["tasks"]
                      if task["kind"] == "investigate")
        self.assertEqual(self.api("POST", f"tasks/{queued['id']}/cancel")[1]["state"], "cancelled")
        release.set()
        self.wait(blocker)
        self.assertEqual(self.api("GET", "cases/review/investigation")[1]["run"]["state"], "paused")


if __name__ == "__main__":
    unittest.main()
