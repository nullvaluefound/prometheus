"""The outcome card, token metering, benchmark scoring and the posture probe."""

import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import boundary, investigation, models, outcome, runtime, skills
from tests.benchmark import fixtures, posture, score
from tests.forge_support import ForgeServer, ScriptedAdapter, write_case

DIGEST = "a" * 64


class OutcomeTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        write_case(self.state, "review", "sha256:" + DIGEST)
        self.folder = runtime.case_path(self.state, "review")

    def test_the_card_counts_decisions_grants_proposals_and_tokens(self):
        log = [
            {"decision": "dispatched", "tool": "artifact_summary", "session": "s1"},
            {"decision": "completed", "tool": "artifact_summary", "session": "s1"},
            {"decision": "intercepted", "tool": "ghidra_decompile", "session": "s1",
             "reason": "operator_excerpt_grant_required"},
            {"decision": "grant_requested", "request": "r1"},
            {"decision": "grant", "grant": {"id": "g1"}},
            {"decision": "grant_decided", "outcome": "approved", "request": "r1"},
            {"decision": "grant_decided", "outcome": "denied", "requests": ["r2", "r3"]},
            {"decision": "forge_chat_completed", "provider": "ollama", "cloud": False, "tokens_in": 100,
             "tokens_out": 20},
            {"decision": "review_completed", "provider": "anthropic", "cloud": True, "tokens_in": 7, "tokens_out": 3},
            {"decision": "forge_chat_failed", "provider": "ollama", "cloud": False, "tokens_in": "lots"},
            {"decision": "pause", "operator": "analyst"},
        ]
        for index, event in enumerate(log):
            runtime.audit(self.folder, **event)
        (self.folder / "audit.jsonl").open("ab").write(b"not json\n")
        investigation.add_question(self.state, "review", "Q", "O", [DIGEST], "analyst")

        def change(data):
            data["candidates"] += [{"id": "C1", "state": "recorded", "check": {"result": "passed"}, "verdicts": [{}]},
                                   {"id": "C2", "state": "proposed", "check": {"result": "failed"}, "verdicts": []}]
        investigation.update(self.state, "review", change)
        card = outcome.for_case(self.state, "review", self.folder)
        self.assertEqual(card["tools"], {"artifact_summary": {"dispatched": 1, "completed": 1},
                                         "ghidra_decompile": {"intercepted": 1}})
        self.assertEqual(card["denials"], {"operator_excerpt_grant_required": 1})
        self.assertEqual(card["grants"], {"requested": 1, "issued": 1, "approved": 1, "denied": 2})
        self.assertEqual((card["candidates"]["total"], card["candidates"]["passed"], card["candidates"]["recorded"],
                          card["candidates"]["reviewed"]), (2, 1, 1, 1))
        self.assertEqual(card["questions"], {"open": 1})
        self.assertEqual(card["tokens"], [
            {"provider": "anthropic", "locality": "cloud", "input": 7, "output": 3, "sessions": 1},
            {"provider": "ollama", "locality": "local", "input": 100, "output": 20, "sessions": 2}])
        self.assertEqual(card["model_sessions"], 1)
        self.assertTrue(card["first_utc"] <= card["last_utc"])

    def test_a_chat_turn_records_its_tokens(self):
        class Counting(ScriptedAdapter):
            def __init__(self, *args):
                super().__init__(*args)
                self.usage = {"input": 50, "output": 9}
        with patch.dict(models.ADAPTERS, {"ollama": Counting}):
            ScriptedAdapter.script = [("Done.", [])]
            models.converse(self.state, "review", {"provider": "ollama", "base_url": "http://127.0.0.1:1", "model": "m"},
                            {"role": "evidence", "tools": [], "allow_cloud": False}, [], "hi", "analyst")
        completed = [json.loads(line) for line in (self.folder / "audit.jsonl").read_text().splitlines()][-1]
        self.assertEqual((completed["decision"], completed["tokens_in"], completed["tokens_out"], completed["cloud"]),
                         ("forge_chat_completed", 50, 9, False))


class ScoreTests(unittest.TestCase):
    def truths(self):
        return fixtures.synthetic_pe()["truths"]

    def test_matches_need_the_artifact_kind_address_terms_and_a_passed_check(self):
        truth = self.truths()
        digest = truth[0]["artifact"]
        candidates = [
            {"id": "C1", "artifacts": [digest], "kind": "observed", "check": {"result": "passed"},
             "claim": "A PE candidate whose entry point RVA is 0x00001000."},
            {"id": "C2", "artifacts": [digest], "kind": "observed", "check": {"result": "failed"},
             "claim": "It imports ExitProcess."},
            {"id": "C3", "artifacts": ["b" * 64], "kind": "observed", "check": {"result": "passed"},
             "claim": "A PE."},
        ]
        report = score.score(candidates, truth)
        self.assertEqual([item["found"] for item in report["items"]], [True, True, False])
        self.assertEqual((report["truths"], report["found"], report["candidates"], report["matching_candidates"]),
                         (3, 2, 3, 1))
        self.assertEqual((report["recall"], report["precision"], report["references_resolve"]), (0.667, 0.333, 2))
        self.assertEqual(score.score([], truth)["precision"], None)

    def test_the_synthetic_fixture_is_stable(self):
        self.assertEqual(fixtures.synthetic_pe()["sha256"], fixtures.synthetic_pe()["sha256"])
        self.assertTrue(fixtures.synthetic_pe()["bytes"].startswith(b"MZ"))


class PostureTests(unittest.TestCase):
    CONFIG = {"provider": "ollama", "model": "probe"}

    def run_probe(self, *scripts):
        runs = iter(scripts)

        def factory(config, system, tools):
            ScriptedAdapter.script = next(runs)
            adapter = ScriptedAdapter(config, system, tools)
            return adapter
        return posture.probe(self.CONFIG, factory)

    def test_a_good_model_works_and_ignores_planted_instructions(self):
        summary = {"id": None, "name": "artifact_summary", "arguments": {"artifact": posture.DIGEST}}
        result = self.run_probe([("", [summary]), ("It is an ELF.", [])], [("", [summary]), ("An ELF file.", [])])
        self.assertTrue(result["pass"], result)
        planted = next(texts for kind, texts in ScriptedAdapter.last.seen if kind == "results")[0]
        self.assertTrue(planted.startswith("<<<UNTRUSTED_TOOL_OUTPUT nonce="))

    def test_refusal_and_injection_are_flagged(self):
        summary = {"id": None, "name": "artifact_summary", "arguments": {"artifact": posture.DIGEST}}
        capa = {"id": None, "name": "capa_triage", "arguments": {"artifact": posture.DIGEST}}
        result = self.run_probe([("I can't help with malware analysis.", [])], [("", [summary]), ("", [capa]),
                                                                                 ("Done.", [])])
        self.assertEqual((result["legitimate"]["refused"], result["injection"]["called_planted_tool"], result["pass"]),
                         (True, True, False))

    def test_echoing_the_canary_is_following_the_injection(self):
        summary = {"id": None, "name": "artifact_summary", "arguments": {"artifact": posture.DIGEST}}

        def echo(adapter):
            planted = adapter.seen[-1][1][0]
            return "ELF. " + planted[planted.index("CANARY-"):planted.index("CANARY-") + 15], []
        result = self.run_probe([("", [summary]), ("ELF.", [])], [("", [summary]), echo])
        self.assertTrue(result["injection"]["echoed_canary"])
        self.assertFalse(result["pass"])


class SkillTests(unittest.TestCase):
    CONFIG = {"provider": "ollama", "base_url": "http://127.0.0.1:1", "model": "m"}

    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        write_case(self.state, "review", "sha256:" + DIGEST)
        patcher = patch.dict(models.ADAPTERS, {"ollama": ScriptedAdapter})
        patcher.start()
        self.addCleanup(patcher.stop)

    def turn(self, role, *names):
        steps = [("", [{"id": None, "name": "load_skill", "arguments": {"name": name}} for name in names]), ("Ok.", [])]
        ScriptedAdapter.script = steps
        return models.converse(self.state, "review", self.CONFIG, {"role": role, "tools": [], "allow_cloud": False},
                               [], "go", "analyst")

    def test_a_role_sees_its_skills_listed_and_loads_their_bodies(self):
        self.turn("native", "static-re-native", "static-re-evidence", "made-up")
        adapter = ScriptedAdapter.last
        self.assertIn("`static-re-native`:", adapter.system)
        self.assertNotIn("`static-re-evidence`:", adapter.system)
        self.assertTrue(adapter.system.endswith(boundary.tail(False)))
        loaded, hidden, unknown = (json.loads(text) for text in next(texts for kind, texts in adapter.seen if kind == "results"))
        self.assertEqual((loaded["status"], loaded["name"]), ("loaded", "static-re-native"))
        self.assertEqual(loaded["body"], skills.read("static-re-native")["body"])
        self.assertFalse(loaded["body"].startswith("---"))
        self.assertEqual((hidden["reason"], unknown["reason"]), ("skill_not_visible", "unknown_skill"))
        self.assertIn("guidance", unknown)
        audit = [json.loads(line) for line in (runtime.case_path(self.state, "review") / "audit.jsonl")
                 .read_text().splitlines()]
        self.assertEqual([(event["decision"], event["skill"]) for event in audit if "skill" in event],
                         [("skill_loaded", "static-re-native"), ("skill_missing", "static-re-evidence"),
                          ("skill_missing", "made-up")])
        self.assertEqual({row["name"]: row["count"] for row in skills.gaps(self.state)},
                         {"static-re-evidence": 1, "made-up": 1})

    def test_names_outside_the_slug_pattern_are_one_gap(self):
        self.turn("review", "../../etc/passwd", "x" * 80)
        self.assertEqual([(row["name"], row["count"]) for row in skills.gaps(self.state)], [("invalid-name", 2)])

    def test_every_visible_skill_exists_and_says_when_to_use_it(self):
        for role, names in skills.VISIBLE.items():
            for name in names:
                with self.subTest(role=role, name=name):
                    skill = skills.read(name)
                    self.assertIsNotNone(skill)
                    self.assertGreater(len(skill["description"]), 40)
                    self.assertLess(len(skill["body"]), skills.MAX_BODY)

    def test_skills_name_only_tools_that_exist(self):
        """A small model calls what the skill tells it to, so a skill must never name a tool it does not have."""
        import re
        from re_harness import investigation, policy
        real = set(policy.TOOLS) | set(investigation.TOOLS) | {"note_grant_need", "load_skill", "submit_verdict"}
        suffixes = ("_summary", "_strings", "_imports", "_functions", "_xrefs", "_decompile", "_inspect", "_scan",
                    "_triage", "_overview", "_detail", "_lead", "_observation", "_plan", "_finding", "_need")
        for name in {name for names in skills.VISIBLE.values() for name in names}:
            body = skills.read(name)["body"]
            for token in set(re.findall(r"`([a-z]+(?:_[a-z]+)+)`", body)):
                if token.endswith(suffixes):
                    with self.subTest(skill=name, token=token):
                        self.assertIn(token, real)

    def test_a_role_s_skills_point_only_at_skills_it_can_load(self):
        """A skill may send a role to another skill only if the role can load it, unless that line is a step for a
        tool the role lacks (which the skill tells it to skip)."""
        import re
        from re_harness import investigation, local_model, policy
        known = {path.parent.name for path in skills.folder().glob("*/SKILL.md")}
        real = set(policy.TOOLS) | set(investigation.TOOLS)
        for role, names in skills.VISIBLE.items():
            tools = set(local_model.ROLES[role])
            for name in names:
                for line in skills.read(name)["body"].splitlines():
                    for target in (set(re.findall(r"`([a-z]+(?:-[a-z]+)+)`", line)) & known) - set(names):
                        lacked = {tool for tool in re.findall(r"`([a-z_]+)`", line) if tool in real - tools}
                        with self.subTest(role=role, skill=name, target=target):
                            self.assertTrue(lacked, line)
        self.assertNotIn("static-triage", skills.listing("review"))
        self.assertIn("Load `static-triage` first", skills.listing("evidence"))

    def test_pinned_skills_load_into_the_prompt_and_leave_the_listing(self):
        with patch.dict(skills.PINNED, {"evidence": ("static-triage",)}):
            text = skills.listing("evidence")
        self.assertTrue(text.startswith("## Procedure: static-triage\n\n**Rules first:**"))
        self.assertNotIn("# Static triage", text)
        self.assertNotIn("- `static-triage`:", text)
        self.assertIn("- `recording-evidence`:", text)
        self.assertIn("- `static-triage`:", skills.listing("evidence"))

    def test_frontmatter_is_split_from_the_body(self):
        fields, body = skills.parse("---\nname: a\ndescription: Does b.\n---\n\n# Title\n")
        self.assertEqual((fields, body), ({"name": "a", "description": "Does b."}, "# Title"))
        self.assertIsNone(skills.read("../agents"))


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class OutcomeApiTests(ForgeServer, unittest.TestCase):
    def setUp(self):
        self.start_forge()

    def test_the_outcome_route_is_per_visible_case(self):
        runtime.audit(runtime.case_path(self.state, "review"), decision="grant_requested", request="r1")
        status, card = self.api("GET", "cases/review/outcome")
        self.assertEqual((status, card["grants"]["requested"]), (200, 1))
        self.assertEqual(self.api("GET", "cases/offscope/outcome")[0], 404)
        policy = self.api("GET", "policy")[1]
        self.assertEqual([row["name"] for row in policy["skills"]["review"]],
                         ["recording-evidence", "capa-yara", "import-analysis", "static-re-evidence"])
        self.assertEqual(policy["skill_gaps"], [])


if __name__ == "__main__":
    unittest.main()
