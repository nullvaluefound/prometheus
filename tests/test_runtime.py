"""Host runtime boundary: engine selection, case records, operator lock and worker containment flags."""

from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from re_harness import case, runtime

DIGEST = "a" * 64
VOLUME = "static-re-" + "1" * 32
RECORD = {"case": "fixture", "image": "sha256:" + DIGEST, "engine": "linux", "volume": VOLUME}


class EngineTests(unittest.TestCase):
    def test_selectors_are_closed(self):
        self.assertEqual(runtime.engine_command("linux"), ["docker", "--host", "unix:///var/run/docker.sock"])
        self.assertEqual(runtime.engine_command("desktop")[:2], ["docker.exe", "--host"])
        self.assertEqual(runtime.engine_command("wsl:Ubuntu-24.04")[:4],
                         ["wsl.exe", "--distribution", "Ubuntu-24.04", "--exec"])
        for engine in ("docker", "wsl:../x", "wsl:", "wsl:-x", "wsl:a b", "wsl:" + "a" * 65, "linux\n",
                       "Linux", "unix:///var/run/docker.sock", None, ["linux"]):
            with self.subTest(engine=engine), self.assertRaises(runtime.RuntimeFailure):
                runtime.engine_command(engine)

    def test_tool_timeouts(self):
        self.assertEqual(runtime.tool_timeout("capa_triage"), 300)
        for name in ("artifact_summary", "yara_scan", "ghidra_decompile", "unknown"):
            self.assertEqual(runtime.tool_timeout(name), 155)


class WorkerFlagTests(unittest.TestCase):
    def run_worker(self, record=RECORD, **kwargs):
        with patch.object(runtime, "volume_exists") as exists, \
                patch.object(runtime, "capped_run", return_value=(0, b"{}")) as run:
            self.assertEqual(runtime.worker(record, ["analyze"], **kwargs), (0, b"{}"))
        command, stdin, request, stderr, timeout, cap = run.call_args.args
        self.assertEqual(command[:3], ["docker", "--host", "unix:///var/run/docker.sock"])
        self.assertEqual(command[-2:], [record["image"], "analyze"])
        self.assertEqual(exists.called, "volume" in record)
        return command, stdin, request, stderr, timeout

    def mounts(self, command):
        return [command[index + 1] for index, value in enumerate(command) if value == "--mount"]

    def test_containment_flags(self):
        command, stdin, request, stderr, timeout = self.run_worker()
        for flag in ("--rm", "--pull=never", "--network=none", "--read-only", "--cap-drop=ALL",
                     "--security-opt=no-new-privileges:true", "--user=65532:65532", "--log-driver=none"):
            self.assertIn(flag, command)
        self.assertNotIn("-i", command)
        self.assertNotIn("--privileged", command)
        self.assertNotIn("host", " ".join(command[3:]).replace("--host", ""))
        self.assertEqual((stdin, request, stderr, timeout), (subprocess.DEVNULL, None, subprocess.DEVNULL, 155))
        self.assertEqual(self.mounts(command), [f"type=volume,source={VOLUME},target=/case,readonly"])

    def test_proxy_environment_is_blanked(self):
        command = self.run_worker()[0]
        env = [command[index + 1] for index, value in enumerate(command) if value == "--env"]
        for key in runtime.PROXY_VARIABLES:
            self.assertIn(key + "=", env)
            self.assertIn(key.lower() + "=", env)
        self.assertTrue(all(value.endswith("=") for value in env))

    def test_writable_mount_and_stdin(self):
        command, stdin, request, _, _ = self.run_worker(writable=True, request=b"{}")
        self.assertEqual(self.mounts(command), [f"type=volume,source={VOLUME},target=/case"])
        self.assertIn("-i", command)
        self.assertEqual((stdin, request), (subprocess.PIPE, b"{}"))
        command, stdin, _, _, _ = self.run_worker(source=7)
        self.assertIn("-i", command)
        self.assertEqual(stdin, 7)

    def test_blank_worker_has_no_mount(self):
        record = {key: RECORD[key] for key in ("image", "engine")}
        command, _, _, stderr, _ = self.run_worker(record, diagnostics=True)
        self.assertEqual(self.mounts(command), [])
        self.assertIsNone(stderr)

    def test_output_path_uses_docker_with_same_flags(self):
        with patch.object(runtime, "volume_exists"), patch.object(runtime, "docker") as docker:
            docker.return_value.returncode = 3
            self.assertEqual(runtime.worker(RECORD, ["export", "case.json"], output=9), (3, b""))
        engine, args = docker.call_args.args
        self.assertEqual(engine, "linux")
        self.assertIn("--network=none", args)
        self.assertNotIn("-i", args)
        self.assertEqual(docker.call_args.kwargs["stdout"], 9)

    def test_invalid_runtime_record_is_refused_before_docker(self):
        for record in ({**RECORD, "image": "static-re-harness:clean"}, {**RECORD, "engine": "docker"}):
            with self.subTest(record=record), patch.object(runtime, "capped_run") as run, \
                    patch.object(runtime, "docker") as docker, self.assertRaises(runtime.RuntimeFailure):
                runtime.worker(record, ["analyze"])
            run.assert_not_called()
            docker.assert_not_called()

    def test_timeout_removes_container(self):
        with patch.object(runtime, "volume_exists"), patch.object(runtime, "docker") as docker, \
                patch.object(runtime, "capped_run", side_effect=subprocess.TimeoutExpired("docker", 1)) as run, \
                self.assertRaises(subprocess.TimeoutExpired):
            runtime.worker(RECORD, ["analyze"], request=b"{}")
        name = run.call_args.args[0][run.call_args.args[0].index("--name") + 1]
        self.assertTrue(name.startswith("static-re-worker-"))
        self.assertEqual(docker.call_args.args, ("linux", ["container", "rm", "-f", name]))


class CaseRecordTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        self.folder = runtime.case_path(self.state, "fixture")
        self.folder.mkdir(parents=True)
        self.scope = {**RECORD, "initialized": True, "paused": False, "grants": []}

    def load(self, **changes):
        case.atomic_json(self.folder / "scope.json", {**self.scope, **changes})
        return runtime.load_case(self.state, "fixture")

    def test_valid_record_loads(self):
        rules = {"sha256": "b" * 64, "rules": 2, "bytes": 90}
        folder, record = self.load(yara_rules=rules)
        self.assertEqual((folder, record["yara_rules"]), (self.folder, rules))
        self.assertEqual(runtime.yara_rules(record), "b" * 64)

    def test_invalid_records_are_refused(self):
        for changes in ({"volume": "static-re-xyz"}, {"volume": "evidence"}, {"volume": VOLUME + "0"},
                        {"paused": "false"}, {"paused": 0}, {"case": "other"}, {"grants": {}},
                        {"initialized": 1}, {"initialized": False}, {"image": "sha256:" + "A" * 64},
                        {"engine": "wsl:../x"}, {"yara_rules": "b" * 64},
                        {"yara_rules": {"sha256": "B" * 64, "rules": 1, "bytes": 1}},
                        {"yara_rules": {"sha256": "b" * 64, "rules": True, "bytes": 1}},
                        {"yara_rules": {"sha256": "b" * 64, "rules": 1}}):
            with self.subTest(changes=changes), self.assertRaises(runtime.RuntimeFailure):
                self.load(**changes)

    def test_pending_case_needs_explicit_allowance(self):
        case.atomic_json(self.folder / "scope.json", {**self.scope, "initialized": False})
        self.assertFalse(runtime.load_case(self.state, "fixture", allow_pending=True)[1]["initialized"])

    def test_case_ids_are_closed(self):
        for case_id in ("../fixture", "Fixture", "-x", "a" * 49, ""):
            with self.subTest(case_id=case_id), self.assertRaises(runtime.RuntimeFailure):
                runtime.load_case(self.state, case_id)

    def test_operator_lock_refuses_second_holder(self):
        with runtime.operator_lock(self.folder):
            self.assertTrue((self.folder / ".operator.lock").exists())
            with self.assertRaises(runtime.RuntimeFailure), runtime.operator_lock(self.folder):
                pass
            self.assertTrue((self.folder / ".operator.lock").exists())
        self.assertFalse((self.folder / ".operator.lock").exists())
        with self.assertRaises(KeyError), runtime.operator_lock(self.folder):
            raise KeyError("released on failure")
        with runtime.operator_lock(self.folder):
            pass


if __name__ == "__main__":
    unittest.main()
