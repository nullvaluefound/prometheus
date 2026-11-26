import datetime as dt
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from re_harness import accounts, cli


class AccountTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)
        fast = patch.dict(accounts.SCRYPT, {"n": 2 ** 10})
        fast.start()
        self.addCleanup(fast.stop)

    def enrol(self, name="analyst", password="correct horse battery"):
        return accounts.complete_setup(self.state, name, accounts.issue_setup(self.state, name), password)

    def test_store_keeps_only_hashes(self):
        code = accounts.issue_setup(self.state, "analyst")
        epoch = accounts.complete_setup(self.state, "analyst", code, "correct horse battery")
        accounts.issue_session(self.state, "analyst", epoch)
        raw = accounts.store_path(self.state).read_text(encoding="ascii")
        self.assertNotIn("correct horse battery", raw)
        self.assertNotIn(code, raw)
        self.assertTrue(json.loads(raw)["accounts"]["analyst"]["password"].startswith("scrypt$"))
        if os.name == "posix":
            self.assertEqual(accounts.store_path(self.state).stat().st_mode & 0o777, 0o600)
            self.assertEqual((accounts.folder(self.state) / "session.key").stat().st_mode & 0o777, 0o600)

    def test_setup_codes_are_single_use_and_expire(self):
        code = accounts.issue_setup(self.state, "analyst")
        later = accounts.utcnow() + dt.timedelta(hours=accounts.SETUP_HOURS, seconds=1)
        with self.assertRaisesRegex(accounts.AccountError, "expired"):
            accounts.complete_setup(self.state, "analyst", code, "correct horse battery", now=later)
        accounts.complete_setup(self.state, "analyst", code, "correct horse battery")
        with self.assertRaises(accounts.AccountError):
            accounts.complete_setup(self.state, "analyst", code, "another good password")

    def test_password_rules(self):
        code = accounts.issue_setup(self.state, "analyst")
        for password, reason in (("short", "at least"), ("x" * 73, "at most"), ("é" * 40, "at most"),
                                 ("Analyst" + "", "at least")):
            with self.subTest(password=password[:10]), self.assertRaisesRegex(accounts.AccountError, reason):
                accounts.complete_setup(self.state, "analyst", code, password)
        accounts.issue_setup(self.state, "longername12")
        with self.assertRaisesRegex(accounts.AccountError, "differ"):
            accounts.complete_setup(self.state, "longername12",
                                    accounts.issue_setup(self.state, "longername12"), "LongerName12")
        with self.assertRaises(accounts.AccountError):
            accounts.issue_setup(self.state, "Bad Name")

    def test_authentication_and_sessions(self):
        epoch = self.enrol()
        self.assertEqual(accounts.authenticate(self.state, "analyst", "correct horse battery"), epoch)
        for name, password in (("analyst", "wrong"), ("ghost", "correct horse battery"), ("../x", "y")):
            self.assertIsNone(accounts.authenticate(self.state, name, password))
        token = accounts.issue_session(self.state, "analyst", epoch)
        self.assertEqual(accounts.session_user(self.state, token), "analyst")
        late = accounts.utcnow() + dt.timedelta(hours=accounts.SESSION_HOURS, seconds=1)
        self.assertIsNone(accounts.session_user(self.state, token, now=late))
        for forged in ("", "abc", token + "x", "e30." + token.split(".")[1], token.replace(".", "..")):
            self.assertIsNone(accounts.session_user(self.state, forged))
        accounts.end_sessions(self.state, "analyst")
        self.assertIsNone(accounts.session_user(self.state, token))

    def test_reset_clears_the_password_and_sessions(self):
        epoch = self.enrol()
        token = accounts.issue_session(self.state, "analyst", epoch)
        accounts.issue_setup(self.state, "analyst")
        self.assertIsNone(accounts.authenticate(self.state, "analyst", "correct horse battery"))
        self.assertIsNone(accounts.session_user(self.state, token))

    def test_change_password(self):
        self.enrol()
        with self.assertRaisesRegex(accounts.AccountError, "current password"):
            accounts.change_password(self.state, "analyst", "nope", "a brand new secret")
        with self.assertRaisesRegex(accounts.AccountError, "not just used"):
            accounts.change_password(self.state, "analyst", "correct horse battery", "correct horse battery")
        accounts.change_password(self.state, "analyst", "correct horse battery", "a brand new secret")
        self.assertIsNotNone(accounts.authenticate(self.state, "analyst", "a brand new secret"))


class ForgeUserCommandTests(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.state = Path(directory.name)

    def run_cli(self, *argv):
        parser, handlers = cli.make_parser()
        args = parser.parse_args(["forge-user", *argv])
        with patch.object(cli, "STATE", self.state), patch.object(cli, "emit") as emit:
            handlers["forge-user"](args)
        return emit.call_args.args[0]

    def test_add_writes_the_code_to_a_private_file_only(self):
        target = self.state / "code.txt"
        result = self.run_cli("add", "analyst", "--code-file", str(target))
        code = target.read_text(encoding="ascii").strip()
        self.assertNotIn("setup_code", result)
        self.assertEqual(result["setup_code_file"], str(target))
        self.assertEqual(len(code), 24)
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.run_cli("add", "analyst")
        with self.assertRaisesRegex(ValueError, "already exists"):
            self.run_cli("reset", "analyst", "--code-file", str(target))
        self.assertIn("setup_code", self.run_cli("reset", "analyst"))
        self.assertEqual(self.run_cli("list")[0]["user"], "analyst")
        self.assertEqual(self.run_cli("remove", "analyst")["decision"], "removed")
        with self.assertRaisesRegex(ValueError, "No such account"):
            self.run_cli("signout", "analyst")


if __name__ == "__main__":
    unittest.main()
