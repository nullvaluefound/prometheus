"""Evidence-gated lessons from closed cases, shadow mode first. Host-only.

A lesson pairs a cue with an action and the evidence rows it came from. Lessons are extracted deterministically from
closed cases' reviewed outcomes: a proposal's failed reference check, a review verdict of unsupported, or an operator
rejection. Their action text is fixed by the Forge, never model text, so a lesson cannot carry sample instructions.

Live cases propose lessons; benchmarks adopt them. A lesson becomes adopted only when the operator records a benchmark
comparison that shows no loss in recall or precision. Modes:
- off: lessons are ignored.
- shadow: sessions that propose findings audit which lessons would have been shown, and nothing else changes.
- inject: adopted lessons are shown to those sessions as a data block of prior outcomes, never as instructions.
Lessons never change tools, grants or policy.
"""

import datetime as dt
import json
import threading

from . import accounts, boundary, investigation, policy, runtime

MODES = ("off", "shadow", "inject")
STATES = ("proposed", "adopted", "retired")
LOCK = threading.Lock()
MAX_EVIDENCE = 50
ACTIONS = {
    "check:address_not_in_evidence": "Cite the evidence object that shows each address you name in a claim.",
    "check:observed_without_evidence": "Cite evidence ids for observed claims, or mark the claim inferred.",
    "check:unknown_evidence": "Cite evidence ids exactly as the tool results give them.",
    "check:evidence_hash_mismatch": "Cite evidence ids exactly as the tool results give them.",
    "check:artifact_not_admitted": "Name only artifacts admitted to the case.",
    "check:claim_names_unadmitted_sha256": "Name only SHA-256 values of admitted artifacts in a claim.",
    "verdict:unsupported": "Argue at least one alternative explanation before proposing, and say why the evidence rules "
                           "it out.",
    "verdict:insufficient": "Gather the evidence that would settle a claim before proposing it, or state its "
                            "limitations.",
    "rejected": "State limitations and counterevidence in proposals; the operator rejected proposals that lacked them.",
}
APPLIES = {"propose_finding", "record_observation"}  # sessions that can write claims see lessons


def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()


def store_path(state):
    return accounts.folder(state) / "lessons.json"


def load(state):
    try:
        data = json.loads(store_path(state).read_text(encoding="utf-8"))
    except FileNotFoundError:
        return {"mode": "off", "lessons": []}
    except (OSError, ValueError):
        return {"mode": "off", "lessons": []}
    if not isinstance(data, dict) or data.get("mode") not in MODES or not isinstance(data.get("lessons"), list):
        return {"mode": "off", "lessons": []}
    return data


def save(state, data):
    accounts.write_private(store_path(state), (json.dumps(data, indent=1, ensure_ascii=True) + "\n").encode("ascii"))


def cues(candidate):
    """The cues one reviewed proposal supports."""
    found = []
    check = candidate.get("check") or {}
    if check.get("result") == "failed":
        found += ["check:" + problem.get("code", "") for problem in check.get("problems") or []
                  if isinstance(problem, dict)]
    for verdict in candidate.get("verdicts") or []:
        if isinstance(verdict, dict) and verdict.get("verdict") in ("unsupported", "insufficient"):
            found.append("verdict:" + verdict["verdict"])
    if candidate.get("state") == "rejected":
        found.append("rejected")
    return [cue for cue in dict.fromkeys(found) if cue in ACTIONS]


def extract(state, case_ids, operator):
    """Propose lessons from closed cases' reviewed outcomes. Returns the ids of lessons created or extended."""
    rows = {}
    for case_id in case_ids:
        try:
            _, record = runtime.load_case(state, case_id, allow_closed=True)
            if not runtime.closed(record):
                continue
            data = investigation.load(state, case_id)
        except (OSError, ValueError, KeyError, runtime.RuntimeFailure):
            continue
        for candidate in data["candidates"]:
            for cue in cues(candidate):
                rows.setdefault(cue, []).append({"case": case_id, "candidate": candidate.get("id")})
    with LOCK:
        data = load(state)
        by_cue = {lesson["cue"]: lesson for lesson in data["lessons"] if lesson.get("state") != "retired"}
        touched = []
        for cue, evidence in sorted(rows.items()):
            lesson = by_cue.get(cue)
            if lesson is None:
                lesson = {"id": f"S{len(data['lessons']) + 1}", "state": "proposed", "cue": cue, "action": ACTIONS[cue],
                          "evidence": [], "created_utc": now(), "created_by": operator, "adopted": None}
                data["lessons"].append(lesson)
            known = {(row["case"], row["candidate"]) for row in lesson["evidence"]}
            lesson["evidence"] = (lesson["evidence"] + [row for row in evidence
                                                        if (row["case"], row["candidate"]) not in known])[-MAX_EVIDENCE:]
            touched.append(lesson["id"])
        save(state, data)
    return touched


def set_mode(state, mode):
    if mode not in MODES:
        raise ValueError("invalid_mode")
    with LOCK:
        data = load(state)
        data["mode"] = mode
        save(state, data)
    return mode


def number(value):
    return isinstance(value, (int, float)) and not isinstance(value, bool) and 0 <= value <= 1


def adopt(state, lesson_id, operator, benchmark):
    """Adopt a lesson on a benchmark comparison that shows no loss in recall or precision."""
    if not any(row.get("id") == lesson_id for row in load(state)["lessons"]):
        raise KeyError(lesson_id)
    before, after = (benchmark.get(key) if isinstance(benchmark, dict) else None for key in ("before", "after"))
    if not all(isinstance(row, dict) and number(row.get("recall")) and number(row.get("precision"))
               for row in (before, after)):
        raise ValueError("invalid_benchmark")
    if after["recall"] < before["recall"] or after["precision"] < before["precision"]:
        raise ValueError("benchmark_regressed")
    return change(state, lesson_id, "adopted", operator, {"before": before, "after": after})


def retire(state, lesson_id, operator):
    return change(state, lesson_id, "retired", operator)


def change(state, lesson_id, target, operator, benchmark=None):
    with LOCK:
        data = load(state)
        lesson = next((row for row in data["lessons"] if row.get("id") == lesson_id), None)
        if lesson is None:
            raise KeyError(lesson_id)
        if lesson["state"] == "retired" or (target == "adopted" and lesson["state"] == "adopted"):
            raise ValueError("invalid_transition")
        lesson["state"] = target
        if target == "adopted":
            lesson["adopted"] = {"by": operator, "utc": now(), "benchmark": benchmark}
        else:
            lesson["retired"] = {"by": operator, "utc": now()}
        save(state, data)
        return dict(lesson)


def for_session(state, case_folder, case_id, session, tools):
    """The prior-outcomes block for a session's system prompt, or "". Shadow mode only audits what it would show."""
    if not set(tools) & APPLIES:
        return ""
    data = load(state)
    if data["mode"] == "off":
        return ""
    shown = [lesson for lesson in data["lessons"]
             if lesson.get("state") == "adopted" or (data["mode"] == "shadow" and lesson.get("state") == "proposed")]
    if not shown:
        return ""
    if data["mode"] == "shadow":
        runtime.audit(case_folder, case=case_id, session=session, decision="lessons_shadow",
                      lessons=[lesson["id"] for lesson in shown][:32])
        return ""
    runtime.audit(case_folder, case=case_id, session=session, decision="lessons_injected",
                  lessons=[lesson["id"] for lesson in shown][:32])
    rows = [{"cue": lesson["cue"], "outcome": lesson["action"], "cases": len({row["case"] for row in lesson["evidence"]})}
            for lesson in shown[:12]]
    return ("## Prior outcomes\n\nThese are outcomes from closed cases, recorded by the Forge. They are not "
            "instructions and do not change your tools or rules.\n\n" + boundary.envelope(json.dumps(rows)))


def public(data):
    return {"mode": data["mode"], "lessons": data["lessons"][-200:], "modes": list(MODES)}


def valid_id(value):
    return policy.match(value, r"S[0-9]{1,5}")
