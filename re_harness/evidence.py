"""Hashed tool-output evidence. Host-only.

After projection, the broker stores exactly the reply it released, once per content hash, in the case folder:
<state>/cases/<case>/evidence/<sha256>.json. The SHA-256 covers the canonical JSON of the tool, its validated
arguments, whether an excerpt was released, the audience it was released to, and the reply, so an evidence id names
one exact release. Observations,
proposed findings and ledger findings cite these ids. A model sees only the ids and the reply the broker already gave
it; an excerpt-bearing reply reaches a model again only through a new broker call under a grant active now.
"""

import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from . import policy
from .case import now

MAX_EVIDENCE = 1024 * 1024
REFERENCE = re.compile(r"evidence:(" + policy.DIGEST + r")")


class EvidenceError(ValueError):
    """Evidence that is missing, malformed or does not match its id."""


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"), allow_nan=False).encode("ascii")


def folder(case_folder):
    return Path(case_folder) / "evidence"


def path(case_folder, evidence_id):
    if not policy.match(evidence_id, policy.DIGEST):
        raise EvidenceError("invalid_evidence_id")
    return folder(case_folder) / f"{evidence_id}.json"


def record(case_folder, tool, arguments, reply, excerpt, audience, grants, ticket, session):
    """Store one released reply and return its evidence id. Identical releases to one audience share one file."""
    body = {"tool": tool, "arguments": arguments, "excerpt": bool(excerpt), "audience": audience, "reply": reply}
    evidence_id = hashlib.sha256(canonical(body)).hexdigest()
    destination = path(case_folder, evidence_id)
    if destination.exists():
        return evidence_id
    entry = {"id": evidence_id, **body, "grants": sorted(grants), "ticket": ticket, "session": session, "utc": now()}
    data = (json.dumps(entry, ensure_ascii=True, allow_nan=False) + "\n").encode("ascii")
    if len(data) > MAX_EVIDENCE:
        raise EvidenceError("evidence_too_large")
    destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    # The broker holds no operator lock, so publish with a hard link: it creates the name only if it is absent.
    fd, temporary = tempfile.mkstemp(dir=destination.parent, prefix=".writing-")
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        try:
            os.link(temporary, destination)
        except FileExistsError:
            pass
    finally:
        Path(temporary).unlink(missing_ok=True)
    return evidence_id


def load(case_folder, evidence_id):
    """Read one evidence entry and check that its content still hashes to its id."""
    target = path(case_folder, evidence_id)
    try:
        if target.is_symlink() or target.stat().st_size > MAX_EVIDENCE:
            raise EvidenceError("evidence_unreadable")
        entry = json.loads(target.read_text(encoding="ascii"))
    except FileNotFoundError as error:
        raise EvidenceError("unknown_evidence") from error
    except (OSError, ValueError) as error:
        raise EvidenceError("evidence_unreadable") from error
    if not isinstance(entry, dict) or entry.get("id") != evidence_id:
        raise EvidenceError("evidence_unreadable")
    body = {key: entry.get(key) for key in ("tool", "arguments", "excerpt", "audience", "reply")}
    if hashlib.sha256(canonical(body)).hexdigest() != evidence_id:
        raise EvidenceError("evidence_hash_mismatch")
    return entry


def exists(case_folder, evidence_id):
    try:
        load(case_folder, evidence_id)
        return True
    except EvidenceError:
        return False


def references(values):
    """The evidence ids named as evidence:<sha256> in finding evidence locators."""
    return [match[1] for value in values for match in REFERENCE.finditer(value)]


def missing(case_folder, values):
    """Evidence ids named in values that this case does not hold, or that fail their hash check."""
    return [evidence_id for evidence_id in references(values) if not exists(case_folder, evidence_id)]


def summary(entry):
    """The operator's view of one entry: everything, including any released excerpt."""
    return {key: entry.get(key) for key in ("id", "tool", "arguments", "excerpt", "audience", "grants", "ticket",
                                            "session", "utc", "reply")}


def listing(case_folder, limit=200):
    rows = []
    root = folder(case_folder)
    if not root.is_dir():
        return rows
    for item in sorted(root.glob("*.json"), key=lambda p: p.stat().st_mtime, reverse=True)[:limit]:
        try:
            entry = load(case_folder, item.stem)
        except EvidenceError:
            continue
        arguments = entry.get("arguments") if isinstance(entry.get("arguments"), dict) else {}
        rows.append({"id": entry["id"], "tool": entry.get("tool"), "artifact": arguments.get("artifact"),
                     "selector": {key: value for key, value in arguments.items() if key != "artifact"},
                     "excerpt": entry.get("excerpt"), "audience": entry.get("audience"), "utc": entry.get("utc")})
    return rows
