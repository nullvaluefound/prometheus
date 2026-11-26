"""In-process change notices for the Forge's live updates. Host-only.

Writers call bump() with topic names such as "tasks", "waiting" or "chat:<case>". The events stream tells signed-in
browsers which topics changed, and the browser re-reads them through the JSON API. A notice carries topic names and
case ids only, never content, so it cannot leak sample text or bypass the API's checks.
"""

import threading

CONDITION = threading.Condition()
KEEP = 512
state = {"version": 0, "recent": []}  # recent holds (version, topic), oldest first


def bump(*topics):
    with CONDITION:
        for topic in topics:
            if topic:
                state["version"] += 1
                state["recent"].append((state["version"], topic))
        del state["recent"][:-KEEP]
        CONDITION.notify_all()


def current():
    with CONDITION:
        return state["version"]


def since(version, timeout):
    """Wait up to timeout seconds for a change after version. Returns (version, topics).

    topics is ["*"] when the caller fell so far behind that some changes were dropped.
    """
    with CONDITION:
        CONDITION.wait_for(lambda: state["version"] > version, timeout)
        recent = state["recent"]
        if state["version"] == version:
            return version, []
        if recent and recent[0][0] > version + 1:
            return state["version"], ["*"]
        return state["version"], sorted({topic for number, topic in recent if number > version})


def case_of(topic):
    """The case id a topic names, or None for global topics."""
    _, _, case_id = topic.partition(":")
    return case_id or None
