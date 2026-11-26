"""Forge model registry and broker-mediated chat across Ollama, OpenAI-compatible and Anthropic providers.

Host-only. Every model tool call goes through server.Broker, so models see only projected, audited results.
API keys are stored in a mode-0600 file in the state directory and are never returned to the browser.
"""

import http.client
import ipaddress
import json
import ssl
import subprocess
import threading
from urllib.parse import urlsplit

from . import accounts, boundary, forge, grant_requests, local_model, policy, runtime, server

PROVIDERS = ("ollama", "openai", "anthropic")
MODEL_ID = r"[a-z0-9][a-z0-9-]{0,31}"
MODEL_NAME = r"[A-Za-z0-9][A-Za-z0-9._:/@-]{0,159}"
DISPLAY_NAME = r"[ -~]{1,64}"
API_KEY = r"[!-~]{1,512}"
MAX_TURNS = local_model.MAX_TURNS
MAX_CALLS = 4
MAX_RESPONSE = 1024 * 1024
MAX_PROMPT = 6000
MAX_HISTORY = 40
# Anthropic models that accept server-side refusal fallbacks.
FALLBACK_MODELS = {"claude-fable-5-2", "claude-fable-5-1", "claude-opus-5-5", "claude-opus-5", "claude-sonnet-5-5"}
PRIVATE_SUFFIXES = (".local", ".lan", ".home.arpa", ".internal", ".localhost")
STORE_LOCK = threading.Lock()
WRAPUP = ("This turn's tool budget is spent, so no further tool calls will run. Without calling tools, write a short "
          "wrap-up for the operator: what you learned, citing SHA-256 values and addresses; the open leads; and which "
          "grant or evidence would help next.")
WITHHELD = ("[An earlier answer is withheld from this model. It drew on excerpts that are not granted to this "
            "model's audience now.]")


class ModelError(ValueError):
    """A refusal that is safe to show the operator."""


def store_path(state):
    return accounts.folder(state) / "models.json"


def load(state):
    path = store_path(state)
    if not path.exists():
        return {"models": {}}
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or not isinstance(data.get("models"), dict):
        raise runtime.RuntimeFailure("Forge model store is invalid")
    return data


def save(state, data):
    accounts.write_private(store_path(state), (json.dumps(data, indent=2, ensure_ascii=True) + "\n").encode("ascii"))


def private_host(host):
    host = (host or "").lower().rstrip(".")
    if host == "localhost" or host.endswith(PRIVATE_SUFFIXES):
        return True
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return False
    return address.is_private or address.is_loopback or address.is_link_local


def is_cloud(config):
    if config["provider"] == "anthropic" or config["model"].endswith(":cloud"):
        return True
    return not private_host(urlsplit(config["base_url"]).hostname)


def public(model_id, config):
    return {"id": model_id, "name": config["name"], "provider": config["provider"], "base_url": config["base_url"],
            "model": config["model"], "cloud": is_cloud(config), "has_key": bool(config.get("api_key"))}


def listing(state):
    return [public(key, value) for key, value in sorted(load(state)["models"].items())]


def get(state, model_id):
    config = load(state)["models"].get(model_id) if isinstance(model_id, str) else None
    if not config:
        raise ModelError("Unknown model.")
    return config


def validate(body, existing=None):
    if not isinstance(body, dict):
        raise ModelError("Send a model object.")
    name, provider, base_url, model = (body.get(key) for key in ("name", "provider", "base_url", "model"))
    if not isinstance(name, str) or not policy.match(name, DISPLAY_NAME):
        raise ModelError("Name the model with 1-64 printable characters.")
    if provider not in PROVIDERS:
        raise ModelError("Provider must be ollama, openai or anthropic.")
    if not isinstance(model, str) or not policy.match(model, MODEL_NAME):
        raise ModelError("Give the provider's exact model name.")
    if not isinstance(base_url, str) or len(base_url) > 200:
        raise ModelError("Give the provider base URL.")
    parts = urlsplit(base_url)
    if (parts.scheme not in ("http", "https") or not parts.hostname or parts.username or parts.password or
            parts.query or parts.fragment or parts.path not in ("", "/", "/v1", "/v1/")):
        raise ModelError("The base URL must be http(s)://host[:port] with an optional /v1 and no credentials.")
    config = {"name": name, "provider": provider, "base_url": base_url.rstrip("/"), "model": model,
              "api_key": (existing or {}).get("api_key")}
    if "api_key" in body:
        key = body["api_key"]
        if key == "" or key is None:
            config["api_key"] = None
        elif isinstance(key, str) and policy.match(key, API_KEY):
            config["api_key"] = key
        else:
            raise ModelError("The API key must be 1-512 printable characters.")
    if parts.scheme == "http" and not private_host(parts.hostname) and config["api_key"]:
        raise ModelError("Send API keys only over HTTPS to a public host.")
    if provider == "anthropic" and not config["api_key"]:
        raise ModelError("Anthropic models need an API key.")
    return config


def put(state, model_id, body, create):
    if not isinstance(model_id, str) or not policy.match(model_id, MODEL_ID):
        raise ModelError("Model IDs are 1-32 lowercase letters, digits or dashes.")
    with STORE_LOCK:
        data = load(state)
        existing = data["models"].get(model_id)
        if create and existing:
            raise ModelError("A model with that ID already exists.")
        if not create and not existing:
            raise ModelError("Unknown model.")
        data["models"][model_id] = validate(body, existing)
        save(state, data)
        return public(model_id, data["models"][model_id])


def delete(state, model_id):
    with STORE_LOCK:
        data = load(state)
        if data["models"].pop(model_id, None) is None:
            raise ModelError("Unknown model.")
        save(state, data)


# ---- Provider transport --------------------------------------------------------------------------------------

def post_json(base_url, path, payload, headers=None, timeout=180):
    parts = urlsplit(base_url)
    port = parts.port or (443 if parts.scheme == "https" else 80)
    if parts.scheme == "https":
        connection = http.client.HTTPSConnection(parts.hostname, port, timeout=timeout,
                                                 context=ssl.create_default_context())
    else:
        connection = http.client.HTTPConnection(parts.hostname, port, timeout=timeout)
    prefix = parts.path.rstrip("/")
    try:
        body = None if payload is None else json.dumps(payload, ensure_ascii=True).encode("ascii")
        connection.request("GET" if body is None else "POST", prefix + path, body=body,
                           headers={"Content-Type": "application/json", **(headers or {})})
        reply = connection.getresponse()
        data = reply.read(MAX_RESPONSE + 1)
    except (OSError, http.client.HTTPException) as error:
        # The host is the operator's own configuration, so naming it is safe.
        raise ModelError(f"Could not reach the model endpoint at {parts.hostname}:{port}.") from error
    finally:
        connection.close()
    if len(data) > MAX_RESPONSE:
        raise ModelError("The model response exceeded its size budget.")
    if reply.status != 200:
        raise ModelError(f"The model endpoint returned HTTP {reply.status}.")
    try:
        return json.loads(data)
    except ValueError as error:
        raise ModelError("The model endpoint did not return JSON.") from error


NOTE_TOOL = "note_grant_need"
NOTE_TEXT = ("Add one short reason to a pending excerpt grant request that the Forge filed for a refused call: what "
             "the excerpt would show and why it matters. The operator sees it as untrusted text.")
NOTE_SCHEMA = {"type": "object", "properties": {
    "request": {"type": "string", "pattern": "^[a-f0-9]{32}$"},
    "reason": {"type": "string", "minLength": 1, "maxLength": grant_requests.MAX_REASON}},
    "required": ["request", "reason"], "additionalProperties": False}


def tool_specs(names, requests=False):
    specs = [(name, policy.TOOLS[name], policy.tool_schema(name)) for name in sorted(names)]
    return specs + ([(NOTE_TOOL, NOTE_TEXT, NOTE_SCHEMA)] if requests else [])


def clean(text):
    return "".join(ch for ch in text if ch in "\n\t" or ch.isprintable())[:MAX_RESPONSE] if isinstance(text, str) else ""


class Ollama:
    def __init__(self, config, system, tools):
        self.config = config
        self.messages = [{"role": "system", "content": system}]
        self.tools = [{"type": "function", "function": {"name": n, "description": d, "parameters": s}}
                      for n, d, s in tools]

    def user(self, text):
        self.messages.append({"role": "user", "content": text})

    def assistant_text(self, text):
        self.messages.append({"role": "assistant", "content": text})

    def step(self, final=False):
        """One model request. A final step offers no tools; the caller also dispatches nothing from it."""
        payload = {"model": self.config["model"], "messages": self.messages, "stream": False,
                   "options": {"num_predict": 2000, "temperature": 0}}
        if not final:
            payload["tools"] = self.tools
        result = post_json(self.config["base_url"], "/api/chat", payload)
        message = result.get("message") if isinstance(result, dict) else None
        if not isinstance(message, dict) or message.get("role") != "assistant":
            raise runtime.RuntimeFailure("Unexpected Ollama response")
        calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function", {}) if isinstance(call, dict) else {}
            calls.append({"id": None, "name": function.get("name"), "arguments": function.get("arguments")})
        self.messages.append({key: message[key] for key in ("role", "content", "tool_calls") if key in message})
        return clean(message.get("content", "")), calls

    def results(self, pairs):
        for call, text in pairs:
            self.messages.append({"role": "tool", "tool_name": call["safe_name"], "content": text})


class OpenAICompatible(Ollama):
    def step(self, final=False):
        path = "/chat/completions" if self.config["base_url"].endswith("/v1") else "/v1/chat/completions"
        headers = {"Authorization": "Bearer " + self.config["api_key"]} if self.config.get("api_key") else {}
        payload = {"model": self.config["model"], "messages": self.messages}
        if self.tools:
            # Earlier tool calls stay in the history, so a final step keeps the schemas and forbids calls.
            payload.update(tools=self.tools, **({"tool_choice": "none"} if final else {}))
        result = post_json(self.config["base_url"], path, payload, headers)
        try:
            message = result["choices"][0]["message"]
        except (KeyError, IndexError, TypeError) as error:
            raise runtime.RuntimeFailure("Unexpected OpenAI-compatible response") from error
        calls = []
        for call in message.get("tool_calls") or []:
            function = call.get("function", {}) if isinstance(call, dict) else {}
            try:
                arguments = json.loads(function.get("arguments") or "{}")
            except (TypeError, ValueError):
                arguments = None
            calls.append({"id": call.get("id"), "name": function.get("name"), "arguments": arguments})
        kept = {"role": "assistant", "content": message.get("content") or ""}
        if message.get("tool_calls"):
            kept["tool_calls"] = message["tool_calls"]
        self.messages.append(kept)
        return clean(message.get("content") or ""), calls

    def results(self, pairs):
        for call, text in pairs:
            self.messages.append({"role": "tool", "tool_call_id": call["id"], "content": text})


class Anthropic:
    """Claude through the official Anthropic Python SDK, with a manual tool loop so the broker sees every call."""

    def __init__(self, config, system, tools):
        try:
            import anthropic
        except ImportError as error:
            raise ModelError("Install the anthropic package in the Forge service environment.") from error
        self.sdk = anthropic
        self.client = anthropic.Anthropic(api_key=config["api_key"], base_url=config["base_url"], timeout=180.0,
                                          max_retries=2)
        self.config = config
        self.system = system
        self.messages = []
        self.tools = [{"name": n, "description": d, "input_schema": s} for n, d, s in tools]

    def user(self, text):
        self.messages.append({"role": "user", "content": text})

    def assistant_text(self, text):
        self.messages.append({"role": "assistant", "content": text})

    def create(self, final=False):
        request = {"model": self.config["model"], "max_tokens": 16000, "system": self.system,
                   "messages": self.messages, "tools": self.tools}
        if final and self.tools:
            request["tool_choice"] = {"type": "none"}
        try:
            if self.config["model"] in FALLBACK_MODELS:
                request["output_config"] = {"effort": "high"}
                return self.client.beta.messages.create(**request, betas=["server-side-fallback-2026-07-01"],
                                                        fallbacks="default")
            return self.client.messages.create(**request)
        except self.sdk.AuthenticationError as error:
            raise ModelError("Anthropic rejected the API key.") from error
        except self.sdk.NotFoundError as error:
            raise ModelError("Anthropic does not know that model name.") from error
        except self.sdk.RateLimitError as error:
            raise ModelError("Anthropic rate-limited the request. Try again shortly.") from error
        except self.sdk.APIStatusError as error:
            raise ModelError(f"Anthropic returned HTTP {error.status_code}.") from error
        except self.sdk.APIConnectionError as error:
            raise ModelError("Could not reach the Anthropic API.") from error

    def step(self, final=False):
        while True:
            response = self.create(final)
            content = response.to_dict()["content"]
            self.messages.append({"role": "assistant", "content": content})
            if response.stop_reason == "pause_turn":
                continue
            break
        if response.stop_reason == "refusal":
            details = getattr(response, "stop_details", None)
            category = getattr(details, "category", None) if details else None
            raise ModelError("The model declined this request" + (f" ({category})." if category else "."))
        text = "\n".join(block.text for block in response.content if block.type == "text")
        calls = [{"id": block.id, "name": block.name, "arguments": block.input}
                 for block in response.content if block.type == "tool_use"]
        return clean(text), calls

    def results(self, pairs):
        self.messages.append({"role": "user", "content": [
            {"type": "tool_result", "tool_use_id": call["id"], "content": text,
             **({"is_error": True} if call.get("error") else {})} for call, text in pairs]})


ADAPTERS = {"ollama": Ollama, "openai": OpenAICompatible, "anthropic": Anthropic}


def test(config):
    """Send one tiny request and report whether the endpoint and model answer."""
    adapter = ADAPTERS[config["provider"]](config, "Reply with the single word ready.", [])
    adapter.user("Are you ready?")
    text, _ = adapter.step()
    return {"ok": True, "detail": (text.strip() or "The model answered with no text.")[:200]}


def replayable(row, active):
    """Model text can quote excerpts it saw. Replay it only while every grant it drew on is active for this audience.

    A row from before rows were stamped has unknown provenance, so it is withheld.
    """
    grants = row.get("grants")
    return (row.get("audience") in ("local", "mcp") and isinstance(grants, list) and
            all(isinstance(grant, str) and grant in active for grant in grants))


def replay(adapter, history, scope, audience):
    """Feed earlier turns to the adapter under the excerpt rule. Returns the grants the replayed text drew on."""
    active = server.active_grant_ids(scope, audience)
    inherited = set()
    for row in history[-MAX_HISTORY:]:
        if row.get("role") == "user" and isinstance(row.get("text"), str):
            adapter.user(row["text"])
        elif row.get("role") == "assistant" and row.get("text"):
            if replayable(row, active):
                adapter.assistant_text(row["text"])
                inherited.update(row["grants"])
            else:
                adapter.assistant_text(WITHHELD)
    return inherited


class Turn:
    """One chat turn's tool handling: broker calls, grant requests filed from denials, and model-facing framing."""

    def __init__(self, state, case_id, broker, role, allowed):
        self.state, self.case_id, self.broker, self.role, self.allowed = state, case_id, broker, role, allowed
        self.requests = bool(allowed & policy.EXCERPT_ONLY)
        self.seen = set()  # SHA-256 values and addresses this session's tool output named
        self.manifest = None

    def names(self):
        return self.allowed | ({NOTE_TOOL} if self.requests else set())

    def admitted(self):
        """The case manifest's SHA-256 values, read once per turn through a read-only Apprentice."""
        if self.manifest is None:
            self.manifest = set(forge.case_ledger(self.broker.current_scope())["artifacts"])
        return self.manifest

    def dispatch(self, name, arguments):
        """Return (display_text, is_error, model_text, extra) for one call."""
        if name == NOTE_TOOL and self.requests:
            return self.note(arguments)
        reply = self.broker.call({"name": name, "arguments": arguments})
        text = reply["content"][0]["text"]
        if not reply["isError"]:
            self.seen |= grant_requests.tokens(text)
            return text, False, boundary.envelope(text), {}
        extra, override = {}, None
        if denial_reason(text) == "operator_excerpt_grant_required":
            extra, override = self.file_request(name, arguments)
        return text, True, boundary.for_model(text, True, name, self.role, extra, override), extra

    def file_request(self, name, arguments):
        """File a pending request for exactly the refused call, after a host-side admission check."""
        try:
            validated = policy.validate(name, arguments)
            if validated["artifact"] not in self.admitted():
                return {}, "artifact_not_admitted"
            row, _ = grant_requests.file(self.state, self.case_id, name, validated, self.broker.audience,
                                         self.broker.session)
        except grant_requests.RequestError as error:
            return {}, str(error)
        except policy.Denied:
            return {}, "not_requestable"
        except FORGE_ERRORS:
            return {}, "admission_unverified"
        return {"status": "pending", "request": row["id"]}, None

    def note(self, arguments):
        try:
            self.broker.current_scope()
            if not isinstance(arguments, dict) or set(arguments) != {"request", "reason"}:
                raise grant_requests.RequestError("invalid_note")
            try:
                known = self.seen | self.admitted()
            except FORGE_ERRORS:
                known = set(self.seen)
            row = grant_requests.note(self.state, self.case_id, arguments["request"], arguments["reason"],
                                      self.broker.session, known)
        except (policy.Denied, grant_requests.RequestError) as error:
            text = json.dumps({"status": "denied", "reason": str(error)})
            return text, True, boundary.for_model(text, True, NOTE_TOOL, self.role), {}
        except FORGE_ERRORS:
            text = json.dumps({"status": "failed", "reason": "request_store_unavailable"})
            return text, True, boundary.for_model(text, True, NOTE_TOOL, self.role), {}
        text = json.dumps({"status": "noted", "request": row["id"]})
        return text, False, text, {}


FORGE_ERRORS = (OSError, ValueError, KeyError, TypeError, RuntimeError, subprocess.SubprocessError)


def denial_reason(text):
    try:
        reply = json.loads(text)
    except ValueError:
        return None
    return reply.get("reason") if isinstance(reply, dict) else None


def converse(state, case_id, config, settings, history, message, operator):
    """Run one user turn through the broker. Returns the display rows to append to the chat.

    Each assistant row is stamped with the audience it was written for and every grant whose excerpts it may quote:
    the grants this turn released plus those of the earlier text it was shown. A turn that reaches MAX_TURNS gets one
    final model step with no tools, and its summary is saved as the answer.
    """
    if not isinstance(message, str) or not 1 <= len(message) <= MAX_PROMPT:
        raise ModelError(f"Send a message of 1-{MAX_PROMPT} characters.")
    cloud = is_cloud(config)
    if cloud and not settings.get("allow_cloud"):
        raise ModelError("This case does not allow cloud models. Enable it on the case Rules tab.")
    role = settings.get("role") if settings.get("role") in local_model.ROLES else "evidence"
    allowed = set(settings.get("tools") or ()) & local_model.ROLES[role]
    broker = server.Broker(state, case_id, allowed, audience="mcp" if cloud else "local")
    scope = broker.current_scope()
    turn = Turn(state, case_id, broker, role, allowed)
    system = boundary.system_prompt((runtime.ROOT / "agents" / role / "AGENTS.md").read_text(encoding="utf-8"),
                                    requests=turn.requests)
    adapter = ADAPTERS[config["provider"]](config, system, tool_specs(allowed, turn.requests))
    inherited = replay(adapter, history, scope, broker.audience)
    adapter.user(message)
    rows = []

    def stamped(found):
        grants = sorted(inherited | broker.released_grants)
        return [{**row, "audience": broker.audience, "grants": grants} if row["role"] == "assistant" else row
                for row in found]

    def finish(text, wrapup=False):
        runtime.audit(broker.folder, case=case_id, session=broker.session, decision="forge_chat_completed",
                      role=role, operator=operator, via="forge", **({"reason": "turn_budget_wrapup"} if wrapup else {}))
        row = {"role": "assistant", "text": text, "model": config["model"]}
        rows.append({**row, "wrapup": True} if wrapup else row)
        return stamped(rows)

    runtime.audit(broker.folder, case=case_id, session=broker.session, decision="forge_chat_started", role=role,
                  provider=config["provider"], cloud=cloud, operator=operator, via="forge")
    try:
        for _ in range(MAX_TURNS):
            broker.current_scope()
            text, calls = adapter.step()
            if not calls:
                return finish(text or "(no answer)")
            if text:
                rows.append({"role": "assistant", "text": text, "model": config["model"]})
            pairs = []
            for index, call in enumerate(calls):
                name = call.get("name")
                call["safe_name"] = name if isinstance(name, str) and name in turn.names() else "intercepted"
                if index >= MAX_CALLS:
                    shown = json.dumps({"status": "denied", "reason": "tool_call_budget_per_turn"})
                    call["error"], extra = True, {}
                    model_text = boundary.for_model(shown, True, name, role)
                else:
                    shown, call["error"], model_text, extra = turn.dispatch(name, call.get("arguments"))
                pairs.append((call, model_text))
                rows.append(tool_row(call["safe_name"], shown, call["error"], extra.get("request")))
            adapter.results(pairs)
        # The budget is spent: one last step with no tools. Code dispatches nothing from it.
        broker.current_scope()
        adapter.user(WRAPUP)
        text, _ = adapter.step(final=True)
        return finish(text or "(The model wrote no wrap-up.)", wrapup=True)
    except Exception:
        try:
            runtime.audit(broker.folder, case=case_id, session=broker.session, decision="forge_chat_failed",
                          role=role, operator=operator, via="forge", reason="forge_chat_session_failed")
        except (OSError, runtime.RuntimeFailure):
            pass
        raise


def tool_row(name, reply_text, error, request=None):
    try:
        reply = json.loads(reply_text)
    except ValueError:
        reply = {}
    if not error:
        return {"role": "tool", "tool": name, "decision": "completed", "text": f"{name} completed"}
    status = reply.get("status") if isinstance(reply, dict) else None
    reason = reply.get("reason") if isinstance(reply, dict) and isinstance(reply.get("reason"), str) else "unknown"
    decision = "intercepted" if status == "denied" else "failed"
    row = {"role": "tool", "tool": name, "decision": decision, "reason": reason[:80],
           "text": f"{name} {decision}: {reason[:80]}"}
    if request:
        row.update(request=request, text=row["text"] + " (grant request pending with the operator)")
    return row


def default_tools(role):
    return sorted(local_model.ROLES[role])
