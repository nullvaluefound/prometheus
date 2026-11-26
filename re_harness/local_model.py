"""Bounded model sessions through the local Ollama API."""

import http.client
import json
import re

from . import boundary, investigation, policy, runtime, server

# Case-state tools dispatch through the broker like sample tools, with no worker run (investigation.py).
NOTES = {"case_overview", "lead_detail", "add_lead", "record_observation", "update_plan"}
ROLES = {
    "intake": {"artifact_summary", "artifact_strings", "yara_scan", "capa_triage"} | NOTES,
    "native": set(policy.TOOLS) | set(investigation.TOOLS),
    "evidence": {"artifact_summary", "artifact_strings", "artifact_imports", "ghidra_functions", "ghidra_xrefs",
                 "yara_scan", "capa_triage"} | set(investigation.TOOLS),
    "review": {"artifact_summary", "artifact_imports", "ghidra_functions", "ghidra_xrefs", "yara_scan", "capa_triage",
               "case_overview", "lead_detail"},
}


def tool_spec(name):
    """(name, description, JSON schema) for a sample tool or a case-state tool."""
    if name in investigation.TOOLS:
        return investigation.spec(name)
    return name, policy.TOOLS[name], policy.tool_schema(name)
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
    reply = ollama(port, "/api/tags")
    tags = reply.get("models") if isinstance(reply, dict) else None
    if not isinstance(tags, list):
        raise runtime.RuntimeFailure("Unexpected local model listing")
    return any(isinstance(item, dict) and item.get("name") == model and isinstance(item.get("size"), int)
               and item["size"] > 0 and not item.get("remote_model") and not item.get("remote_host")
               for item in tags)


def chat(state, case_id, port, model, role, question):
    if not 1024 <= port <= 65535 or not 1 <= len(question) <= 6000:
        raise runtime.RuntimeFailure("Invalid local port or prompt length")
    broker = server.Broker(state, case_id, ROLES[role], audience="local")
    broker.current_scope()
    if not installed(port, model):
        raise runtime.RuntimeFailure("Select an exact installed local Ollama model name")
    # The role body first, then the code-owned rules, so the Forge's own text is the final word.
    instructions = boundary.system_prompt((runtime.ROOT / "agents" / role / "AGENTS.md").read_text(encoding="utf-8"))
    messages = [{"role": "system", "content": instructions}, {"role": "user", "content": question}]
    tools = [{"type": "function", "function": {"name": name, "description": text, "parameters": schema}}
             for name, text, schema in map(tool_spec, sorted(ROLES[role]))]
    runtime.audit(broker.folder, case=case_id, session=broker.session, decision="local_model_started", role=role)
    try:
        for _ in range(MAX_TURNS):
            broker.current_scope()
            result = ollama(port, "/api/chat", {"model": model, "messages": messages, "tools": tools,
                                              "stream": False, "options": {"num_predict": 1400, "temperature": 0}})
            message = result.get("message") if isinstance(result, dict) else None
            if not isinstance(message, dict) or result.get("done") is not True or message.get("role") != "assistant":
                raise runtime.RuntimeFailure("Unexpected local model response")
            calls = message.get("tool_calls") or []
            text = message.get("content", "")
            if not isinstance(text, str) or not isinstance(calls, list) or len(calls) > 4:
                raise runtime.RuntimeFailure("Local model exceeded its tool-call budget")
            if not calls:
                broker.current_scope()
                runtime.audit(broker.folder, case=case_id, session=broker.session, decision="local_model_completed",
                              role=role)
                # Keep terminal control characters out of human-facing model text.
                return "".join(ch for ch in text if ch in "\n\t" or ch.isprintable())
            messages.append({key: message[key] for key in ("role", "content", "tool_calls", "thinking")
                             if key in message})
            for call in calls:
                function = call.get("function", {}) if isinstance(call, dict) else {}
                if not isinstance(function, dict):
                    function = {}
                reply = broker.call({"name": function.get("name"), "arguments": function.get("arguments")})
                name = function.get("name")
                safe_name = name if isinstance(name, str) and name in ROLES[role] else "intercepted"
                # Results are framed as untrusted data; refusals stay platform text with fixed guidance.
                content = boundary.for_model(reply["content"][0]["text"], reply["isError"], name, role)
                messages.append({"role": "tool", "tool_name": safe_name, "content": content})
        raise runtime.RuntimeFailure("Local model turn budget exhausted")
    except Exception:
        # A fixed reason keeps sample-derived exception text out of the audit log.
        try:
            runtime.audit(broker.folder, case=case_id, session=broker.session, decision="local_model_failed",
                          role=role, reason="local_model_session_failed")
        except (OSError, runtime.RuntimeFailure):
            pass
        raise
