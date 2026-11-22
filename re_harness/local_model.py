"""Bounded model sessions through the local Ollama API."""

import http.client
import json
import re

from . import policy, runtime, server

ROLES = {
    "intake": {"artifact_summary", "artifact_strings"},
    "native": set(policy.TOOLS),
    "evidence": {"artifact_summary", "artifact_strings", "ghidra_functions", "ghidra_xrefs"},
    "review": {"artifact_summary", "ghidra_functions", "ghidra_xrefs"},
}
MAX_TURNS = 8
MAX_MODEL_RESPONSE = 128 * 1024


def ollama(port, path, payload=None):
    connection = http.client.HTTPConnection("127.0.0.1", port=port, timeout=120)
    try:
        value = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("ascii")
        connection.request("GET" if value is None else "POST", path, body=value,
                           headers={"Content-Type": "application/json"})
        reply = connection.getresponse()
        if reply.status != 200:
            raise runtime.RuntimeFailure(f"Local Ollama returned HTTP {reply.status}")
        body = reply.read(MAX_MODEL_RESPONSE + 1)
    finally:
        connection.close()
    if len(body) > MAX_MODEL_RESPONSE:
        raise runtime.RuntimeFailure("Local model response exceeded its size budget")
    return server.strict_json(body)


def installed(port, model):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:/-]{0,159}", model) or model.endswith(":cloud"):
        return False
    tags = ollama(port, "/api/tags")["models"]
    return any(item["name"] == model and item.get("size", 0) > 0
               and not item.get("remote_model") and not item.get("remote_host") for item in tags)


def chat(state, case_id, port, model, role, question):
    if not 1024 <= port <= 65535 or not 1 <= len(question) <= 6000:
        raise runtime.RuntimeFailure("Invalid local port or prompt length")
    broker = server.Broker(state, case_id, ROLES[role], audience="local")
    broker.current_scope()
    if not installed(port, model):
        raise runtime.RuntimeFailure("Select an exact installed local Ollama model name")
    instructions = (runtime.ROOT / "agents" / role / "AGENTS.md").read_text(encoding="utf-8")
    messages = [{"role": "system", "content": instructions}, {"role": "user", "content": question}]
    tools = [{"type": "function", "function": {"name": name, "description": policy.TOOLS[name],
              "parameters": policy.tool_schema(name)}} for name in sorted(ROLES[role])]
    runtime.audit(broker.folder, case=case_id, session=broker.session, decision="local_model_started", role=role)
    for _ in range(MAX_TURNS):
        broker.current_scope()
        result = ollama(port, "/api/chat", {"model": model, "messages": messages, "tools": tools,
                                          "stream": False, "options": {"num_predict": 1400, "temperature": 0}})
        message = result["message"]
        if result.get("done") is not True or message.get("role") != "assistant":
            raise runtime.RuntimeFailure("Unexpected local model response")
        calls = message.get("tool_calls") or []
        text = message.get("content", "")
        if not isinstance(text, str) or not isinstance(calls, list) or len(calls) > 4:
            raise runtime.RuntimeFailure("Local model exceeded its tool-call budget")
        if not calls:
            broker.current_scope()
            runtime.audit(broker.folder, case=case_id, session=broker.session, decision="local_model_completed", role=role)
            # Keep terminal control characters out of human-facing model text.
            return "".join(ch for ch in text if ch in "\n\t" or ch.isprintable())
        messages.append({key: message[key] for key in ("role", "content", "tool_calls", "thinking") if key in message})
        for call in calls:
            function = call.get("function", {}) if isinstance(call, dict) else {}
            if not isinstance(function, dict):
                function = {}
            reply = broker.call({"name": function.get("name"), "arguments": function.get("arguments")})
            name = function.get("name")
            safe_name = name if isinstance(name, str) and name in ROLES[role] else "intercepted"
            messages.append({"role": "tool", "tool_name": safe_name, "content": reply["content"][0]["text"]})
    raise runtime.RuntimeFailure("Local model turn budget exhausted")
