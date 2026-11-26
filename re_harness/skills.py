"""On-demand procedure for Forge chat models. Host-only.

Skills are the git-reviewed SKILL.md files under .agents/skills. A chat session's prompt lists the name and
description of each skill its role may see, and load_skill returns one body. Skills are read-only and never change
tools, grants or policy. Requests for a skill the role cannot load are audited and kept as a "skill gaps" list for the
operator, because they show procedure the models wanted and did not have.
"""

import datetime as dt
import json
import re
import threading

from . import accounts, policy, runtime

NAME = r"[a-z0-9][a-z0-9-]{0,63}"
MAX_BODY = 32 * 1024
TOOL = "load_skill"
TEXT = "Load the full procedure of one skill listed in your instructions, by its name."
SCHEMA = {"type": "object", "properties": {"name": {"type": "string", "pattern": "^" + NAME + "$"}},
          "required": ["name"], "additionalProperties": False}
# Which skills each role may load. Review checks findings, so it sees the evidence procedure only.
VISIBLE = {
    "intake": ("static-malware-re",),
    "native": ("static-malware-re", "static-re-native"),
    "evidence": ("static-malware-re", "static-re-evidence"),
    "review": ("static-re-evidence",),
}
LOCK = threading.Lock()


def folder():
    return runtime.ROOT / ".agents" / "skills"


def parse(text):
    """Split a SKILL.md into (frontmatter fields, body)."""
    fields, body = {}, text
    match = re.match(r"---\n(.*?)\n---\n?", text, re.DOTALL)
    if match:
        for line in match[1].splitlines():
            key, _, value = line.partition(":")
            if key.strip() in ("name", "description"):
                fields[key.strip()] = value.strip()
        body = text[match.end():]
    return fields, body.strip()


def read(name):
    if not policy.match(name, NAME):
        return None
    path = folder() / name / "SKILL.md"
    try:
        if path.is_symlink() or not path.is_file() or path.stat().st_size > MAX_BODY:
            return None
        fields, body = parse(path.read_text(encoding="utf-8").replace("\r\n", "\n"))
    except (OSError, UnicodeError):
        return None
    return {"name": name, "description": fields.get("description", "")[:300], "body": body}


def visible(role):
    """[(name, description)] for the skills this role may load."""
    rows = []
    for name in VISIBLE.get(role, ()):
        skill = read(name)
        if skill:
            rows.append((name, skill["description"]))
    return rows


def listing(role):
    rows = visible(role)
    if not rows:
        return ""
    return ("## Skills you can load\n\nCall `load_skill` with a name to read its procedure when the task calls for it.\n\n"
            + "\n".join(f"- `{name}`: {description}" for name, description in rows))


def gaps_path(state):
    return accounts.folder(state) / "skill_gaps.json"


def gaps(state):
    try:
        data = json.loads(gaps_path(state).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(data, dict):
        return []
    rows = [{"name": name, **value} for name, value in data.items()
            if policy.match(name, NAME) and isinstance(value, dict)]
    return sorted(rows, key=lambda row: row.get("last_utc") or "", reverse=True)[:100]


def record_gap(state, name, role):
    key = name if isinstance(name, str) and policy.match(name, NAME) else "invalid-name"
    with LOCK:
        try:
            data = json.loads(gaps_path(state).read_text(encoding="utf-8"))
            data = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            data = {}
        row = data.get(key) if isinstance(data.get(key), dict) else {"count": 0, "roles": []}
        row["count"] = int(row.get("count", 0)) + 1
        row["roles"] = sorted(set(row.get("roles") or []) | {role})[:8]
        row["last_utc"] = dt.datetime.now(dt.timezone.utc).isoformat()
        data[key] = row
        if len(data) > 200:
            for stale in sorted(data, key=lambda item: data[item].get("last_utc") or "")[:len(data) - 200]:
                data.pop(stale, None)
        accounts.write_private(gaps_path(state), (json.dumps(data, indent=1, ensure_ascii=True) + "\n").encode("ascii"))
    return key


def load(state, case_folder, case_id, session, role, arguments):
    """Handle one load_skill call. Returns (reply, is_error). Loads and misses are audited by name only."""
    name = arguments.get("name") if isinstance(arguments, dict) and set(arguments) == {"name"} else None
    skill = read(name) if isinstance(name, str) and name in VISIBLE.get(role, ()) else None
    if skill is None:
        key = record_gap(state, name, role)
        runtime.audit(case_folder, case=case_id, session=session, decision="skill_missing", skill=key, role=role)
        exists = isinstance(name, str) and read(name) is not None
        return {"status": "denied", "reason": "skill_not_visible" if exists else "unknown_skill"}, True
    runtime.audit(case_folder, case=case_id, session=session, decision="skill_loaded", skill=name, role=role)
    return {"status": "loaded", "name": name, "body": skill["body"]}, False
