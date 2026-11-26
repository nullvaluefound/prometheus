import json
import os
import unittest
from unittest.mock import patch

from re_harness import forge, forge_api, models, runtime
from re_harness.case import atomic_json
from tests.forge_support import ForgeServer, write_case


def ledger(digest):
    return {"title": "Review <img src=x>", "mode": "static",
            "findings": [{"id": "F0001", "kind": "inferred", "confidence": "medium", "claim": "Claim",
                          "evidence": ["RVA 0x5120"], "artifacts": [digest]}],
            "artifacts": {digest: {"size": 16, "hashes": {}, "provenance": [
                {"source": "Operator handoff", "completeness": "complete", "parent": None, "relation": "",
                 "acquired_utc": "2026-11-25T00:00:00+00:00"}]}, "not-a-digest": {"size": 1}}}


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class ForgeApiTests(ForgeServer, unittest.TestCase):
    def setUp(self):
        self.start_forge()

    def audit(self, case="review"):
        path = runtime.case_path(self.state, case) / "audit.jsonl"
        return [json.loads(line) for line in path.read_text(encoding="ascii").splitlines()] if path.exists() else []

    def test_overview_lists_only_visible_cases(self):
        status, overview = self.api("GET", "overview")
        self.assertEqual(status, 200)
        self.assertEqual({row["id"]: row["status"] for row in overview["cases"]}, {"review": "Ready", "frozen": "Paused"})
        self.assertTrue(all(row["verified"] for row in overview["apprentices"]))
        self.assertEqual(overview["tasks"], {"queued": 0, "running": None, "recent": []})
        for route in ("cases/offscope", "cases/missing", "cases/Review", "cases/..%2Freview"):
            with self.subTest(route=route):
                self.assertEqual(self.api("GET", route)[0], 404)
        self.assertEqual(self.api("GET", "nothing")[0], 404)

    def test_case_detail_reads_the_ledger_and_tolerates_its_absence(self):
        with patch.object(forge, "case_ledger", return_value=ledger(self.digest)) as read:
            status, detail = self.api("GET", "cases/review")
        self.assertEqual(status, 200)
        self.assertEqual(read.call_args.args[0]["case"], "review")
        self.assertEqual([a["sha256"] for a in detail["ledger"]["artifacts"]], [self.digest])
        self.assertEqual(detail["ledger"]["findings"][0]["id"], "F0001")
        self.assertEqual(detail["settings"], {"model": None, "allow_cloud": False, "role": "evidence",
                                              "tools": sorted(forge_api.local_model.ROLES["evidence"])})
        self.assertEqual(self.api("GET", "cases")[1]["cases"][1]["artifacts"], 1)
        with patch.object(forge, "case_ledger", side_effect=runtime.RuntimeFailure("ledger_unavailable")):
            self.assertIsNone(self.api("GET", "cases/review")[1]["ledger"])

    def test_pause_and_resume_are_audited_with_the_operator(self):
        self.assertEqual(self.api("POST", "cases/review/pause"), (200, {"status": "Paused"}))
        self.assertTrue(runtime.load_case(self.state, "review")[1]["paused"])
        self.assertEqual(self.api("POST", "cases/review/resume"), (200, {"status": "Ready"}))
        self.assertEqual([(e["decision"], e["operator"], e["via"]) for e in self.audit()],
                         [("pause", "analyst", "forge"), ("resume", "analyst", "forge")])
        (runtime.case_path(self.state, "review") / ".operator.lock").write_text("1", encoding="ascii")
        self.assertEqual(self.api("POST", "cases/review/pause")[0], 409)

    def test_closed_case_refuses_changes(self):
        write_case(self.state, "sealed", self.image)
        folder = runtime.case_path(self.state, "sealed")
        atomic_json(folder / "scope.json", {**runtime.read_json(folder / "scope.json"), "closed": True,
                                            "closed_utc": "2026-11-25T10:00:00+00:00"})
        self.app.visible.add("sealed")
        for method, route, value in (("POST", "cases/sealed/pause", None), ("POST", "cases/sealed/report", None),
                                     ("POST", "cases/sealed/tools/artifact_summary", {"artifact": self.digest}),
                                     ("POST", "cases/sealed/chat", {"message": "hi"})):
            with self.subTest(route=route):
                self.assertEqual(self.api(method, route, value)[1]["error"], "case_closed")
        self.assertEqual(self.api("GET", "cases/sealed")[1]["status"], "Closed")

    def test_json_bodies_are_typed_and_bounded(self):
        self.assertEqual(self.api("POST", "models", raw=b"{}", content_type="text/plain")[0], 400)
        self.assertEqual(self.api("POST", "models", raw=b'{"id": 1, "id": 2}')[0], 400)
        self.assertEqual(self.api("POST", "models", raw=b"[" * 70000)[0], 413)

    def test_settings_keep_cloud_models_behind_an_explicit_opt_in(self):
        self.assertEqual(self.api("POST", "models", {"id": "claude", "name": "Claude", "provider": "anthropic",
                                                     "base_url": "https://api.anthropic.com",
                                                     "model": "claude-opus-5-5", "api_key": "sk-test"})[0], 200)
        base = {"model": "claude", "allow_cloud": False, "role": "evidence", "tools": ["artifact_summary"]}
        self.assertEqual(self.api("PUT", "cases/review/settings", base)[1]["error"], "cloud_not_allowed")
        self.assertEqual(self.api("PUT", "cases/review/settings", {**base, "tools": ["ghidra_decompile"]})[0], 400)
        self.assertEqual(self.api("PUT", "cases/review/settings", {**base, "role": "root"})[0], 400)
        status, settings = self.api("PUT", "cases/review/settings", {**base, "allow_cloud": True})
        self.assertEqual((status, settings["model"], settings["allow_cloud"]), (200, "claude", True))
        self.assertEqual(self.audit()[-1]["decision"], "forge_settings_changed")
        self.assertEqual(self.api("DELETE", "models/claude")[1]["error"], "model_in_use")

    def test_models_never_return_keys(self):
        body = {"id": "lab-qwen", "name": "Lab Qwen", "provider": "ollama", "base_url": "http://10.0.0.20:11434",
                "model": "qwen3:32b"}
        status, model = self.api("POST", "models", body)
        self.assertEqual((status, model["cloud"], model["has_key"]), (200, False, False))
        self.assertEqual(self.api("POST", "models", body)[0], 400)
        status, model = self.api("PUT", "models/lab-qwen", {**body, "api_key": "secret-value"})
        self.assertTrue(model["has_key"])
        self.assertNotIn("secret-value", json.dumps(self.api("GET", "models")[1]))
        self.assertTrue(self.api("PUT", "models/lab-qwen", body)[1]["has_key"])
        self.assertFalse(self.api("PUT", "models/lab-qwen", {**body, "api_key": ""})[1]["has_key"])
        self.assertEqual((self.state / "forge" / "models.json").stat().st_mode & 0o777, 0o600)
        for bad in ({"base_url": "http://example.com", "api_key": "k"}, {"base_url": "ftp://10.0.0.2"},
                    {"base_url": "https://user:pw@example.com"}, {"provider": "other"}, {"model": "a b"},
                    {"provider": "anthropic", "base_url": "https://api.anthropic.com"}):
            with self.subTest(bad=bad):
                self.assertEqual(self.api("POST", "models", {**body, "id": "other", **bad})[0], 400)
        self.assertTrue(self.api("POST", "models", {**body, "id": "remote", "base_url": "https://llm.example.com"})[1]["cloud"])
        self.assertEqual(self.api("DELETE", "models/lab-qwen"), (200, {"deleted": "lab-qwen"}))

    def test_tool_runs_as_an_audited_operator_task(self):
        reply = {"tool": "artifact_summary", "artifact": self.digest, "artifact_bytes": 16,
                 "summary": {"size": 16, "format_hint": "ELF", "strings_count": 1, "strings_truncated": False}}
        with patch.object(forge_api.runtime, "worker", return_value=(0, json.dumps(reply).encode())) as worker, \
                patch.object(forge_api.projection, "project", side_effect=lambda value, *args: value):
            self.assertEqual(self.api("POST", "cases/review/tools/artifact_summary", {"artifact": "../x"})[0], 400)
            self.assertEqual(self.api("POST", "cases/review/tools/run_ghidra_script", {"artifact": self.digest})[0], 404)
            status, accepted = self.api("POST", "cases/review/tools/artifact_summary", {"artifact": self.digest})
            self.assertEqual(status, 202)
            task = self.wait(accepted["task"])
        self.assertEqual((task["state"], task["operator"], task["kind"]), ("succeeded", "analyst", "tool"))
        self.assertEqual(task["result"]["summary"]["format_hint"], "ELF")
        request = json.loads(worker.call_args.kwargs["request"])
        self.assertEqual((request["tool"], request["excerpt"]), ("artifact_summary", True))
        self.assertEqual([(e["decision"], e["via"]) for e in self.audit()],
                         [("operator_requested", "forge"), ("operator_completed", "forge")])
        self.assertEqual(self.api("GET", "tasks?case=review")[1]["tasks"][0]["id"], task["id"])
        status, accepted = self.api("POST", "cases/frozen/tools/artifact_summary", {"artifact": self.digest})
        failed = self.wait(accepted["task"])
        self.assertEqual((failed["state"], failed["error"]), ("failed", "The case is paused. Resume it first."))

    def test_grants_are_created_and_revoked(self):
        body = {"tool": "artifact_strings", "artifact": self.digest, "offset": 0, "limit": 10, "audience": "mcp",
                "minutes": 5}
        for bad in ({"tool": "artifact_summary"}, {"audience": "everyone"}, {"minutes": 61}, {"minutes": "5"}):
            with self.subTest(bad=bad):
                self.assertEqual(self.api("POST", "cases/review/grants", {**body, **bad})[0], 400)
        status, grant = self.api("POST", "cases/review/grants", body)
        self.assertEqual((status, grant["tool"], grant["selector"]), (200, "artifact_strings", {"offset": 0, "limit": 10}))
        self.assertEqual(len(runtime.load_case(self.state, "review")[1]["grants"]), 1)
        self.assertEqual(self.api("POST", "cases/frozen/grants", body)[1]["error"], "grant_refused")
        self.assertEqual(self.api("DELETE", f"cases/review/grants/{'0' * 32}")[0], 404)
        self.assertEqual(self.api("DELETE", f"cases/review/grants/{grant['id']}"), (200, {"revoked": grant["id"]}))
        self.assertEqual(runtime.load_case(self.state, "review")[1]["grants"], [])

    def test_upload_is_streamed_ingested_and_cleaned_up(self):
        seen = {}

        def ingest(args):
            seen.update(data=args.input.read_bytes(), source=args.source, completeness=args.completeness)
            print(json.dumps({"sha256": "b" * 64, "size": 5}))
        with patch.object(forge_api.cli, "operator_action", side_effect=ingest):
            route = "cases/review/artifacts?source=Mail%20gateway&completeness=partial"
            self.assertEqual(self.api("POST", "cases/review/artifacts?source=http://x", raw=b"x",
                                      content_type="application/octet-stream")[0], 400)
            self.assertEqual(self.api("POST", route, raw=b"MZ\x00\x01\x02", content_type="text/plain")[0], 400)
            status, accepted = self.api("POST", route, raw=b"MZ\x00\x01\x02", content_type="application/octet-stream")
            task = self.wait(accepted["task"])
        self.assertEqual(task["result"], {"sha256": "b" * 64, "size": 5})
        self.assertEqual(seen, {"data": b"MZ\x00\x01\x02", "source": "Mail gateway", "completeness": "partial"})
        self.assertEqual(list((self.state / "forge" / "uploads").iterdir()), [])
        self.assertEqual(self.api("POST", "cases/frozen/artifacts?source=x", raw=b"x",
                                  content_type="application/octet-stream")[1]["error"], "case_paused")

    def test_chat_runs_the_selected_model_through_a_task(self):
        self.assertEqual(self.api("POST", "cases/review/chat", {"message": "hi"})[1]["error"], "no_model")
        self.api("POST", "models", {"id": "lab", "name": "Lab", "provider": "ollama",
                                    "base_url": "http://127.0.0.1:11434", "model": "qwen3:32b"})
        self.api("PUT", "cases/review/settings", {"model": "lab", "allow_cloud": False, "role": "evidence",
                                                 "tools": ["artifact_summary"]})
        rows = [{"role": "tool", "tool": "artifact_summary", "decision": "completed", "text": "artifact_summary completed"},
                {"role": "assistant", "text": "It is an ELF.", "model": "qwen3:32b"}]
        with patch.object(forge_api.models, "converse", return_value=rows) as converse:
            status, accepted = self.api("POST", "cases/review/chat", {"message": "What is it?"})
            self.assertEqual(status, 202)
            self.assertEqual(self.wait(accepted["task"])["state"], "succeeded")
        self.assertEqual(converse.call_args.args[5], "What is it?")
        status, chat = self.api("GET", "cases/review/chat")
        self.assertEqual([m["role"] for m in chat["messages"]], ["user", "tool", "assistant"])
        self.assertEqual(chat["messages"][0]["operator"], "analyst")
        self.assertFalse(chat["busy"])
        with patch.object(forge_api.models, "converse", side_effect=models.ModelError("The model declined this request.")):
            self.wait(self.api("POST", "cases/review/chat", {"message": "again"})[1]["task"])
        self.assertEqual(self.api("GET", "cases/review/chat")[1]["messages"][-1]["error"],
                         "The model declined this request.")
        self.assertEqual(self.api("POST", "cases/review/chat", {"message": ""})[0], 400)
        self.assertEqual(self.api("DELETE", "cases/review/chat"), (200, {"cleared": True}))
        self.assertEqual(self.api("GET", "cases/review/chat")[1]["messages"], [])

    def test_case_creation_is_queued(self):
        self.app.visible.clear()
        for bad in ({"id": "Bad", "title": "x"}, {"id": "ok", "title": "https://x"}, {"id": "review", "title": "Again"}):
            with self.subTest(bad=bad):
                self.assertIn(self.api("POST", "cases", bad)[0], (400, 409))
        with patch.object(forge_api.cli, "init_case", side_effect=lambda args: write_case(
                self.state, args.case, self.image)) as init:
            status, accepted = self.api("POST", "cases", {"id": "new-case", "title": "Dropper from mail"})
            self.assertEqual(status, 202)
            self.assertEqual(self.wait(accepted["task"])["state"], "succeeded")
        self.assertEqual(init.call_args.args[0].title, "Dropper from mail")
        row = next(r for r in self.api("GET", "cases")[1]["cases"] if r["id"] == "new-case")
        self.assertEqual(row["title"], "Dropper from mail")

    def test_policy_describes_the_broker(self):
        status, value = self.api("GET", "policy")
        tools = {tool["name"]: tool for tool in value["tools"]}
        self.assertTrue(tools["artifact_imports"]["excerpt_only"])
        self.assertEqual(tools["capa_triage"]["timeout_s"], 300)
        self.assertIn("run_ghidra_script", value["denied"])
        self.assertEqual(value["limits"]["chat_max_calls_per_turn"], models.MAX_CALLS)

    def test_queued_task_can_be_cancelled(self):
        release = __import__("threading").Event()
        first = self.app.tasks.submit("report", "review", "slow", "analyst", lambda: release.wait(5) and {})
        second = self.app.tasks.submit("report", "review", "next", "analyst", lambda: {})
        self.assertEqual(self.api("POST", f"tasks/{second['id']}/cancel")[1]["state"], "cancelled")
        self.assertEqual(self.api("POST", f"tasks/{first['id']}/cancel")[0], 409)
        release.set()
        self.assertEqual(self.wait(first)["state"], "succeeded")
        self.assertEqual(self.api("GET", "tasks/" + "f" * 32)[0], 404)


class ModelAdapterTests(unittest.TestCase):
    def test_cloud_detection(self):
        def config(provider, url, model="m"):
            return {"provider": provider, "base_url": url, "model": model}
        self.assertFalse(models.is_cloud(config("ollama", "http://127.0.0.1:11434")))
        self.assertFalse(models.is_cloud(config("openai", "http://gpu.home.arpa:8000/v1")))
        self.assertTrue(models.is_cloud(config("ollama", "http://127.0.0.1:11434", "gpt-oss:120b:cloud")))
        self.assertTrue(models.is_cloud(config("openai", "https://api.openai.com")))
        self.assertTrue(models.is_cloud(config("anthropic", "http://10.0.0.5")))

    def test_unreachable_endpoint_is_reported_by_host(self):
        with self.assertRaisesRegex(models.ModelError, "Could not reach the model endpoint at 127.0.0.1:9"):
            models.post_json("http://127.0.0.1:9", "/api/chat", {}, timeout=3)

    def test_tool_rows_report_interceptions(self):
        self.assertEqual(models.tool_row("artifact_imports", json.dumps(
            {"status": "denied", "reason": "operator_excerpt_grant_required"}), True)["decision"], "intercepted")
        self.assertEqual(models.tool_row("artifact_summary", "{}", False)["decision"], "completed")


if __name__ == "__main__":
    unittest.main()
