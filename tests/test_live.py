"""Live change notices: the events module, the Forge's event stream, and failed tasks on the waiting list."""

import os
import socket
import threading
import time
import unittest
from unittest.mock import patch

from re_harness import events, forge
from tests.forge_support import ForgeServer


class EventTests(unittest.TestCase):
    def test_since_reports_changed_topics_once(self):
        start = events.current()
        events.bump("chat:review", None, "tasks", "chat:review")
        version, topics = events.since(start, 0)
        self.assertEqual(topics, ["chat:review", "tasks"])
        self.assertEqual(events.since(version, 0), (version, []))
        self.assertEqual(events.case_of("chat:review"), "review")
        self.assertIsNone(events.case_of("tasks"))

    def test_a_reader_that_fell_behind_is_told_to_reload_everything(self):
        start = events.current()
        events.bump(*[f"case:c{index}" for index in range(events.KEEP + 5)])
        self.assertEqual(events.since(start, 0)[1], ["*"])

    def test_since_wakes_when_a_writer_bumps(self):
        start = events.current()
        threading.Timer(0.1, events.bump, args=("tasks",)).start()
        began = time.monotonic()
        self.assertEqual(events.since(start, 5)[1], ["tasks"])
        self.assertLess(time.monotonic() - began, 4)


@unittest.skipUnless(os.name == "posix", "Forge uses Linux Unix sockets")
class StreamTests(ForgeServer, unittest.TestCase):
    def setUp(self):
        self.start_forge()
        for patcher in (patch.object(forge, "STREAM_SECONDS", 1.5), patch.object(forge, "KEEPALIVE_SECONDS", 0.2)):
            patcher.start()
            self.addCleanup(patcher.stop)

    def stream(self, headers):
        """Read one whole event stream, bumping topics once it is open."""
        lines = ["GET /prometheus/api/events HTTP/1.1", "Host: forge", "Connection: close"]
        lines += [f"{name}: {value}" for name, value in headers.items()]
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as sock:
            sock.settimeout(6)
            sock.connect(str(self.path))
            sock.sendall(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"))
            first = sock.recv(65536)
            if b" 200 " in first.split(b"\r\n", 1)[0]:
                events.bump("chat:review", "chat:offscope", "tasks")
            data = first
            while chunk := sock.recv(65536):
                data += chunk
        return data.decode("ascii")

    def test_a_signed_in_browser_gets_topic_names_for_visible_cases_only(self):
        reply = self.stream(self.operator)
        head, _, body = reply.partition("\r\n\r\n")
        self.assertIn("Content-Type: text/event-stream", head)
        self.assertIn("X-Accel-Buffering: no", head)
        self.assertIn("Cache-Control: no-store", head)
        self.assertIn("retry: 5000", body)
        self.assertIn('event: change\ndata: {"topics": ["chat:review", "tasks"]}', body)
        self.assertNotIn("offscope", body)
        self.assertIn(": keepalive", body)

    def test_the_stream_needs_a_session(self):
        reply = self.stream({})
        self.assertTrue(reply.startswith("HTTP/1.0 401"), reply[:40])
        self.assertNotIn("event:", reply)

    def test_failed_tasks_wait_until_dismissed(self):
        failed = self.wait(self.app.tasks.submit("report", "review", "Broken report", "analyst",
                                                 lambda: (_ for _ in ()).throw(RuntimeError("x"))))
        done = self.wait(self.app.tasks.submit("report", "review", "Fine report", "analyst", lambda: {}))
        items = self.api("GET", "overview")[1]["waiting"]["items"]
        self.assertEqual([(item["kind"], item["id"]) for item in items], [("task_failed", failed["id"])])
        self.assertEqual(self.api("GET", "cases/review")[1]["waiting"], 1)
        self.assertEqual(self.api("POST", f"tasks/{done['id']}/dismiss")[1]["error"], "task_not_failed")
        self.assertTrue(self.api("POST", f"tasks/{failed['id']}/dismiss")[1]["dismissed"])
        self.assertEqual(self.api("GET", "overview")[1]["waiting"]["count"], 0)
        self.assertEqual(self.api("POST", "tasks/" + "f" * 32 + "/dismiss")[0], 404)


if __name__ == "__main__":
    unittest.main()
