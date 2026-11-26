"""Deterministic scoring of proposed findings against known properties of benign fixtures.

A truth item names an artifact SHA-256, the kind it must be claimed as, an optional address, and terms the claim must
contain. A proposal matches a truth item when it cites that artifact, claims a compatible kind, names the address and
contains every term, case-insensitively. Observed truths also need the proposal's reference check to have passed. The
report always gives its denominators.
"""

from re_harness import grant_requests

OBSERVED = ("observed", "corroborated")


def matches(candidate, truth):
    if truth["artifact"] not in (candidate.get("artifacts") or []):
        return False
    kind = candidate.get("kind")
    if truth["kind"] == "observed":
        if kind not in OBSERVED or (candidate.get("check") or {}).get("result") != "passed":
            return False
    elif kind not in ("inferred", *OBSERVED):
        return False
    claim = candidate.get("claim") or ""
    if truth.get("address") and hex(int(truth["address"], 16)) not in grant_requests.tokens(claim):
        return False
    lowered = claim.lower()
    return all(term.lower() in lowered for term in truth.get("terms", ()))


def score(candidates, truths):
    items, matched = [], set()
    for truth in truths:
        found = [row.get("id") for row in candidates if matches(row, truth)]
        matched.update(found)
        items.append({"truth": truth["id"], "found": bool(found), "by": found})
    found = sum(item["found"] for item in items)
    checked = sum((row.get("check") or {}).get("result") == "passed" for row in candidates)
    return {
        "truths": len(truths), "found": found, "recall": round(found / len(truths), 3) if truths else None,
        "candidates": len(candidates), "matching_candidates": len(matched),
        "precision": round(len(matched) / len(candidates), 3) if candidates else None,
        "references_resolve": checked, "items": items,
    }
