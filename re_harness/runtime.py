"""Trusted host state and the fixed Docker invocation boundary."""

import contextlib
import datetime as dt
import json
import os
import re
import shutil
import subprocess
import threading
import time
import uuid
from pathlib import Path

from . import policy
from .case import atomic_json, now

ROOT = Path(__file__).resolve().parent.parent
LOCAL = Path(os.environ.get("XDG_STATE_HOME", Path.home() / ".local" / "state"))
# Windows app packaging can virtualize writes under AppData. Keep the default state
# in the user profile so a regular terminal and a packaged client see the same files.
DEFAULT_STATE = Path.home() / ".static-re-harness" if os.name == "nt" else LOCAL / "StaticREHarness"
STATE = Path(os.environ.get("STATIC_RE_STATE_DIR", DEFAULT_STATE)).resolve()
TAG = "static-re-harness:clean"
IMAGE = r"sha256:[0-9a-f]{64}"
VOLUME = r"static-re-[0-9a-f]{32}"
ENGINE = r"(?:desktop|linux|wsl:[A-Za-z0-9][A-Za-z0-9_.-]{0,63})"
PROXY_VARIABLES = ("HTTP_PROXY", "HTTPS_PROXY", "FTP_PROXY", "ALL_PROXY", "NO_PROXY")


class RuntimeFailure(RuntimeError):
    """A controlled operator-facing error."""


def engine_command(engine):
    if not policy.match(engine, ENGINE):
        raise RuntimeFailure("Invalid local engine selector")
    if engine.startswith("wsl:"):
        return ["wsl.exe", "--distribution", engine[4:], "--exec", "/usr/bin/docker",
                "--host", "unix:///var/run/docker.sock"]
    if engine == "desktop":
        return ["docker.exe", "--host", "npipe:////./pipe/dockerDesktopLinuxEngine"]
    return ["docker", "--host", "unix:///var/run/docker.sock"]


def docker(engine, args, **kwargs):
    return subprocess.run(engine_command(engine) + args, cwd=ROOT, shell=False, **kwargs)


def require_engine(engine):
    args = ["info", "--format", "{{.OSType}}/{{.Architecture}}"]
    try:
        result = docker(engine, args, timeout=20, capture_output=True, check=False)
    except (OSError, subprocess.TimeoutExpired) as error:
        raise RuntimeFailure("The selected local Docker engine is unavailable") from error
    output = result.stdout.replace(b"\0", b"").strip()
    if result.returncode or output not in (b"linux/x86_64", b"linux/amd64"):
        raise RuntimeFailure("The selected engine must be running amd64 Linux containers")


def require_build_space(engine):
    # A WSL dynamic disk can advertise hundreds of GiB inside Linux while its host drive is full.
    drive = Path(os.environ.get("LOCALAPPDATA", Path.home())) if os.name == "nt" else Path("/var/lib/docker")
    if os.name == "nt" and engine.startswith("wsl:"):
        import winreg

        registry = r"Software\Microsoft\Windows\CurrentVersion\Lxss"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, registry) as distros:
            total = winreg.QueryInfoKey(distros)[0]
            for index in range(total):
                with winreg.OpenKey(distros, winreg.EnumKey(distros, index)) as entry:
                    try:
                        if winreg.QueryValueEx(entry, "DistributionName")[0].casefold() == engine[4:].casefold():
                            drive = Path(winreg.QueryValueEx(entry, "BasePath")[0])
                            break
                    except FileNotFoundError:
                        continue
    if not drive.exists():
        drive = Path.home() if os.name == "nt" else Path("/")
    free = shutil.disk_usage(drive).free / 1024**3
    if free < 8:
        raise RuntimeFailure(f"Docker image build needs about 8 GiB of host headroom. {free:.2f} GiB is available.")


def case_path(state, case_id):
    if not policy.match(case_id, policy.CASE_ID):
        raise RuntimeFailure("Invalid case ID")
    return state / "cases" / case_id


def read_json(path):
    return json.loads(path.read_text(encoding="utf-8"))


def load_baseline(state):
    record = read_json(state / "baseline.json")
    validate_runtime(record)
    return record


def validate_runtime(record):
    if not policy.match(record.get("image"), IMAGE) or not policy.match(record.get("engine"), ENGINE):
        raise RuntimeFailure("Invalid baseline or case runtime record")


def closed(record):
    return record.get("closed") is True


def valid_utc(value):
    try:
        return isinstance(value, str) and dt.datetime.fromisoformat(value).tzinfo is not None
    except ValueError:
        return False


def load_case(state, case_id, *, allow_pending=False, allow_closed=False):
    """Load a validated case scope. A closed case is refused unless the caller only reads it."""
    folder = case_path(state, case_id)
    record = read_json(folder / "scope.json")
    validate_runtime(record)
    if record.get("case") != case_id or not policy.match(record.get("volume"), VOLUME):
        raise RuntimeFailure("Invalid case scope record")
    if (type(record.get("paused")) is not bool or not isinstance(record.get("grants"), list) or
            type(record.get("initialized")) is not bool):
        raise RuntimeFailure("Invalid case policy record")
    if ("closed" in record or "closed_utc" in record) and (
            record.get("closed") is not True or not valid_utc(record.get("closed_utc")) or
            record["grants"] or not record["initialized"]):
        raise RuntimeFailure("Invalid case closure record")
    if not allow_pending and not record["initialized"]:
        raise RuntimeFailure("Case setup is incomplete")
    if "yara_rules" in record:
        rules = record["yara_rules"]
        if (not isinstance(rules, dict) or not policy.match(rules.get("sha256"), policy.DIGEST) or
                type(rules.get("rules")) is not int or type(rules.get("bytes")) is not int):
            raise RuntimeFailure("Invalid case YARA rules record")
    if closed(record) and not allow_closed:
        raise RuntimeFailure("Case is closed")
    return folder, record


def yara_rules(record):
    """The SHA-256 of the case's operator-imported YARA rules, or a denial when none are imported."""
    if "yara_rules" not in record:
        raise policy.Denied("yara_rules_not_imported")
    return record["yara_rules"]["sha256"]


def tool_timeout(name):
    # capa runs its own vivisect analysis with a 240 second provider budget.
    return 300 if name == "capa_triage" else 155


@contextlib.contextmanager
def operator_lock(folder):
    folder.mkdir(parents=True, exist_ok=True)
    path = folder / ".operator.lock"
    try:
        with path.open("x", encoding="utf-8") as lock:
            lock.write(str(os.getpid()))
    except FileExistsError as error:
        raise RuntimeFailure("Another operator command holds this lock") from error
    try:
        yield
    finally:
        path.unlink(missing_ok=True)


def audit(folder, **event):
    line = json.dumps({"utc": now(), **event}, ensure_ascii=True, allow_nan=False).encode("ascii") + b"\n"
    flags = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)
    fd = os.open(folder / "audit.jsonl", flags, 0o600)
    try:
        if os.write(fd, line) != len(line):
            raise RuntimeFailure("Incomplete audit write")
        os.fsync(fd)
    finally:
        os.close(fd)


def volume_exists(record):
    result = docker(record["engine"], ["volume", "inspect", "--format", "{{json .Labels}}", record["volume"]],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=12, check=False)
    expected = {"io.static-re.case": record["case"], "io.static-re.role": "evidence"}
    if result.returncode or json.loads(result.stdout.replace(b"\0", b"")) != expected:
        raise RuntimeFailure("The case evidence volume is absent or has the wrong identity")


def capped_run(command, stdin, request, stderr, timeout, cap):
    deadline = time.monotonic() + timeout
    with subprocess.Popen(command, cwd=ROOT, stdin=stdin, stdout=subprocess.PIPE, stderr=stderr,
                          shell=False) as process:
        captured = []
        finished = threading.Event()

        def read_output():
            try:
                captured.append(process.stdout.read(cap + 1))
            finally:
                finished.set()

        reader = threading.Thread(target=read_output, daemon=True)
        reader.start()
        try:
            if request is not None:
                # Broker requests have a fixed schema and fit in a single small pipe write.
                with process.stdin:
                    process.stdin.write(request)
            if not finished.wait(max(0, deadline - time.monotonic())):
                raise subprocess.TimeoutExpired(command[0], timeout)
            if not captured or len(captured[0]) > cap:
                raise RuntimeFailure("Worker output exceeds the response budget")
            return process.wait(timeout=max(0, deadline - time.monotonic())), captured[0]
        finally:
            if process.poll() is None:
                process.kill()
            reader.join(timeout=2)


def worker(record, args, *, source=None, request=None, output=None, writable=False, timeout=155,
           cap=policy.MAX_LINE, diagnostics=False):
    validate_runtime(record)
    engine = record["engine"]
    container = "static-re-worker-" + uuid.uuid4().hex
    flags = ["run", "--rm", "--pull=never", "--name", container, "--platform=linux/amd64",
             "--network=none", "--read-only", "--cap-drop=ALL", "--security-opt=no-new-privileges:true",
             "--user=65532:65532", "--pids-limit=96", "--cpus=2", "--memory=3g", "--memory-swap=3g",
             "--ulimit", "fsize=268435456:268435456", "--log-driver=none",
             "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=1g,mode=1777",
             "--label", "io.static-re.role=worker"]
    for key in PROXY_VARIABLES:
        flags += ["--env", key + "=", "--env", key.lower() + "="]
    if "volume" in record:
        volume_exists(record)
        mount = f"type=volume,source={record['volume']},target=/case"
        if not writable:
            mount += ",readonly"
        flags += ["--mount", mount]
    if source is not None or request is not None:
        flags.append("-i")
    stderr = None if diagnostics else subprocess.DEVNULL
    stdin = source if source is not None else (subprocess.PIPE if request is not None else subprocess.DEVNULL)
    docker_args = flags + [record["image"], *args]
    try:
        if output is None:
            return capped_run(engine_command(engine) + docker_args, stdin, request, stderr, timeout, cap)
        result = docker(engine, docker_args, stdin=None if request is not None else stdin, input=request,
                        stdout=output, stderr=stderr, timeout=timeout, check=False)
        return result.returncode, b""
    except (subprocess.TimeoutExpired, RuntimeFailure, KeyboardInterrupt, OSError):
        with contextlib.suppress(OSError, subprocess.SubprocessError):
            docker(engine, ["container", "rm", "-f", container], stdout=subprocess.DEVNULL,
                   stderr=subprocess.DEVNULL, timeout=20, check=False)
        raise


def identify_image(engine, reference):
    result = docker(engine, ["image", "inspect", "--format", "{{.Id}}", reference],
                    stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=20, check=False)
    found = result.stdout.replace(b"\0", b"").decode("ascii").strip()
    if result.returncode or not re.fullmatch(IMAGE, found):
        raise RuntimeFailure("Docker image identity is unavailable")
    return found


def publish_baseline(state, engine, image):
    record = {"engine": engine, "image": image, "created_utc": now()}
    code, data = worker(record, ["selftest"], timeout=660, diagnostics=True)
    if code:
        raise RuntimeFailure("Baseline provider or isolation self-test failed")
    record["verification"] = json.loads(data)
    atomic_json(state / "baseline.json", record)
    return record
