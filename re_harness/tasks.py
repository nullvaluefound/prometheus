"""Forge task queue: one background thread runs Apprentice work in submission order. Host-only."""

import datetime as dt
import json
import queue
import threading
import uuid

from . import accounts, events, policy, runtime

KINDS = ("create_case", "ingest", "tool", "chat", "model_test", "report", "split", "review", "record_finding",
         "investigate", "side_question", "link_cases")
MAX_RESULT = 2 * 1024 * 1024
KEEP = 500


class TaskError(Exception):
    """A failure whose message is fixed text written for the operator, never sample-derived."""


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def safe_error(error):
    if isinstance(error, (TaskError, policy.Denied)):
        return str(error)
    if isinstance(error, runtime.RuntimeFailure):
        # RuntimeFailure messages are fixed strings in this codebase.
        return str(error)[:300]
    return "The task failed. Check the case audit and the Forge service log."


class TaskQueue:
    def __init__(self, state):
        self.folder = state / "forge" / "tasks"
        self.folder.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.lock = threading.Lock()
        self.pending = queue.Queue()
        self.jobs = {}
        self.tasks = {}
        for path in self.folder.glob("*.json"):
            try:
                task = json.loads(path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                continue
            if isinstance(task, dict) and task.get("state") in ("queued", "running"):
                task.update(state="failed", error="The Forge restarted before this task finished.",
                            finished_utc=now())
                self.save(task)
            if isinstance(task, dict) and isinstance(task.get("id"), str):
                self.tasks[task["id"]] = task
        self.thread = threading.Thread(target=self.run, name="forge-tasks", daemon=True)
        self.thread.start()

    def save(self, task):
        accounts.write_private(self.folder / f"{task['id']}.json",
                               (json.dumps(task, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii"))
        events.bump("tasks", "waiting" if task["state"] == "failed" else None,
                    f"case:{task['case']}" if task.get("case") else None)

    def submit(self, kind, case, title, operator, job):
        if kind not in KINDS:
            raise ValueError("unknown task kind")
        task = {"id": uuid.uuid4().hex, "kind": kind, "case": case, "title": title[:160], "state": "queued",
                "operator": operator, "created_utc": now(), "started_utc": None, "finished_utc": None,
                "result": None, "error": None}
        with self.lock:
            self.tasks[task["id"]] = task
            self.jobs[task["id"]] = job
            self.save(task)
            self.prune()
        self.pending.put(task["id"])
        return dict(task)

    def prune(self):
        if len(self.tasks) <= KEEP:
            return
        finished = sorted((t for t in self.tasks.values() if t["state"] not in ("queued", "running")),
                          key=lambda t: t["created_utc"])
        for task in finished[:len(self.tasks) - KEEP]:
            self.tasks.pop(task["id"], None)
            (self.folder / f"{task['id']}.json").unlink(missing_ok=True)

    def get(self, task_id):
        with self.lock:
            task = self.tasks.get(task_id)
            return dict(task) if task else None

    def listing(self, case=None, limit=100):
        with self.lock:
            rows = [dict(t) for t in self.tasks.values() if case is None or t["case"] == case]
        rows.sort(key=lambda t: t["created_utc"], reverse=True)
        return rows[:limit]

    def busy(self, case, kind):
        with self.lock:
            return any(t["case"] == case and t["kind"] == kind and t["state"] in ("queued", "running")
                       for t in self.tasks.values())

    def dismiss(self, task_id):
        """Take a failed task off the operator's waiting list."""
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                raise KeyError(task_id)
            if task["state"] != "failed":
                return None
            task["dismissed"] = True
            self.save(task)
            return dict(task)

    def cancel(self, task_id):
        with self.lock:
            task = self.tasks.get(task_id)
            if not task:
                raise KeyError(task_id)
            if task["state"] != "queued":
                return None
            task.update(state="cancelled", finished_utc=now())
            self.jobs.pop(task_id, None)
            self.save(task)
            return dict(task)

    def run(self):
        while True:
            task_id = self.pending.get()
            with self.lock:
                task = self.tasks.get(task_id)
                job = self.jobs.pop(task_id, None)
                if not task or task["state"] != "queued" or job is None:
                    continue
                task.update(state="running", started_utc=now())
                self.save(task)
            try:
                result = job()
                encoded = json.dumps(result, ensure_ascii=True, allow_nan=False)
                if len(encoded) > MAX_RESULT:
                    raise TaskError("The result exceeded the 2 MiB display budget. Use the operator CLI.")
                outcome = {"state": "succeeded", "result": result}
            except Exception as error:  # every failure is recorded with a fixed, display-safe message
                outcome = {"state": "failed", "error": safe_error(error)}
            with self.lock:
                task.update(**outcome, finished_utc=now())
                self.save(task)
