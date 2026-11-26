import { useState, type FormEvent } from "react";
import { PROVIDERS, api, type ModelConfig, type ModelInput, type Provider, type Task } from "../api";
import { TaskOutcome } from "../components/ResultView";
import { useToast } from "../components/toast";
import { Badge, ConfirmButton, Empty, ErrorNote, Loading, Panel, RefreshButton, TaskChip } from "../components/ui";
import { MODEL_ID, MODEL_ID_PATTERN, isRecord, list, txt } from "../format";
import { errorMessage, isTerminal, useDocumentTitle, useResource, useTask } from "../hooks";

const PRESETS: Record<Provider, { base_url: string; model: string; label: string }> = {
  ollama: { base_url: "http://127.0.0.1:11434", model: "", label: "Ollama" },
  openai: { base_url: "https://api.openai.com", model: "", label: "OpenAI-compatible" },
  anthropic: { base_url: "https://api.anthropic.com", model: "claude-opus-5-5", label: "Anthropic" },
};
const PRESET_URLS = new Set(Object.values(PRESETS).map((preset) => preset.base_url));
const PRESET_MODELS = new Set(Object.values(PRESETS).map((preset) => preset.model));

type Editing = { mode: "new" } | { mode: "edit"; model: ModelConfig } | null;

export function ModelsPage() {
  useDocumentTitle("Models");
  const models = useResource((signal) => api.models({ signal }), "models");
  const [editing, setEditing] = useState<Editing>(null);
  const rows = list<ModelConfig>(models.data?.models).filter(isRecord);

  return (
    <>
      <p className="crumb">
        <a href="#/">Forge</a> / Models
      </p>
      <div className="page-head">
        <h1>Models</h1>
        <div className="page-actions">
          <RefreshButton onClick={models.reload} busy={models.loading && Boolean(models.data)} />
          <button type="button" onClick={() => setEditing({ mode: "new" })} disabled={editing?.mode === "new"}>
            Add model
          </button>
        </div>
      </div>
      <p className="muted lede">
        Plug in a local Ollama daemon, any OpenAI-compatible endpoint or Anthropic. Each case picks its chat model on its Rules &amp; grants tab.
        Cloud models see a case only after that case allows cloud models. API keys are write-only: the Forge never sends them back.
      </p>

      {editing && (
        <ModelForm
          key={editing.mode === "edit" ? `edit:${editing.model.id}` : "new"}
          editing={editing.mode === "edit" ? editing.model : null}
          onDone={() => {
            setEditing(null);
            models.reload();
          }}
          onCancel={() => setEditing(null)}
        />
      )}

      {models.error && <ErrorNote message={models.error} onRetry={models.reload} />}
      {!models.data && !models.error && <Loading label="Loading models…" />}
      {models.data &&
        (rows.length === 0 ? (
          <section className="panel">
            <Empty>No models configured. Add one to chat with a case.</Empty>
          </section>
        ) : (
          <ul className="model-grid">
            {rows.map((model) => (
              <li key={txt(model.id)}>
                <ModelCard model={model} onEdit={() => setEditing({ mode: "edit", model })} onDeleted={models.reload} />
              </li>
            ))}
          </ul>
        ))}
    </>
  );
}

function ModelCard({ model, onEdit, onDeleted }: { model: ModelConfig; onEdit: () => void; onDeleted: () => void }) {
  const toast = useToast();
  const [test, setTest] = useState<Task | null>(null);
  const [starting, setStarting] = useState(false);
  const tracked = useTask(test?.id ?? null, { initial: test });
  const task = tracked.task ?? test;
  const testing = starting || (task !== null && !isTerminal(task.state));

  const runTest = async () => {
    setStarting(true);
    try {
      const reply = await api.testModel(model.id);
      setTest(reply.task);
    } catch (error) {
      toast(errorMessage(error), "err");
    } finally {
      setStarting(false);
    }
  };

  const remove = async () => {
    try {
      await api.deleteModel(model.id);
      toast(`Model ${model.id} deleted.`, "ok");
      onDeleted();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <article className="model-card">
      <div className="model-card-head">
        <h2>{txt(model.name) || txt(model.id)}</h2>
        <span className="badges">
          {model.cloud ? <Badge tone="warn">Cloud</Badge> : <Badge tone="ok">Local</Badge>}
          {model.has_key ? <Badge tone="info">Key set</Badge> : <Badge>No key</Badge>}
        </span>
      </div>
      <dl className="kv kv-tight">
        <div>
          <dt>ID</dt>
          <dd>
            <code>{txt(model.id)}</code>
          </dd>
        </div>
        <div>
          <dt>Provider</dt>
          <dd>{PRESETS[model.provider]?.label ?? txt(model.provider)}</dd>
        </div>
        <div>
          <dt>Base URL</dt>
          <dd>
            <code>{txt(model.base_url)}</code>
          </dd>
        </div>
        <div>
          <dt>Model</dt>
          <dd>
            <code>{txt(model.model)}</code>
          </dd>
        </div>
      </dl>
      {task && (
        <div className="model-test" aria-live="polite">
          <p className="task-line">
            <TaskChip state={task.state} />
            <span>{task.state === "queued" ? "Test queued…" : task.state === "running" ? "Contacting the model…" : "Connection test"}</span>
          </p>
          {isTerminal(task.state) && <TaskOutcome task={task} />}
        </div>
      )}
      <div className="card-actions">
        <button type="button" className="btn-small" onClick={runTest} disabled={testing}>
          {testing ? "Testing…" : "Test"}
        </button>
        <button type="button" className="btn-secondary btn-small" onClick={onEdit}>
          Edit
        </button>
        <ConfirmButton label="Delete" prompt={`Delete ${model.id}?`} confirmLabel="Delete" onConfirm={remove} />
      </div>
    </article>
  );
}

function ModelForm({ editing, onDone, onCancel }: { editing: ModelConfig | null; onDone: () => void; onCancel: () => void }) {
  const toast = useToast();
  const [id, setId] = useState(editing?.id ?? "");
  const [name, setName] = useState(editing?.name ?? "");
  const [provider, setProvider] = useState<Provider>(editing?.provider ?? "ollama");
  const [baseUrl, setBaseUrl] = useState(editing?.base_url ?? PRESETS.ollama.base_url);
  const [modelName, setModelName] = useState(editing?.model ?? "");
  const [apiKey, setApiKey] = useState("");
  const [clearKey, setClearKey] = useState(false);
  const [saving, setSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const changeProvider = (next: Provider) => {
    setProvider(next);
    // Prefill only fields that are empty or still hold another preset's value.
    if (!baseUrl.trim() || PRESET_URLS.has(baseUrl.trim())) setBaseUrl(PRESETS[next].base_url);
    if (!modelName.trim() || PRESET_MODELS.has(modelName.trim())) setModelName(PRESETS[next].model);
  };

  const submit = async (event: FormEvent) => {
    event.preventDefault();
    setError(null);
    const body: ModelInput = {
      id: id.trim(),
      name: name.trim(),
      provider,
      base_url: baseUrl.trim(),
      model: modelName.trim(),
    };
    if (!MODEL_ID.test(body.id)) {
      setError("The ID must be 1 to 32 lowercase letters, digits or hyphens, starting with a letter or digit.");
      return;
    }
    if (!body.name || !body.model) {
      setError("Give the model a display name and a provider model name.");
      return;
    }
    let url: URL | null = null;
    try {
      url = new URL(body.base_url);
    } catch {
      url = null;
    }
    if (!url || (url.protocol !== "http:" && url.protocol !== "https:")) {
      setError("The base URL must be an http or https URL.");
      return;
    }
    if (editing && clearKey) body.api_key = "";
    else if (apiKey) body.api_key = apiKey;
    setSaving(true);
    try {
      if (editing) await api.updateModel(editing.id, body);
      else await api.createModel(body);
      setApiKey("");
      toast(editing ? `Model ${body.id} updated.` : `Model ${body.id} added.`, "ok");
      onDone();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSaving(false);
    }
  };

  return (
    <Panel title={editing ? `Edit ${editing.id}` : "Add a model"} className="model-form">
      <form className="stack-sm" onSubmit={submit} noValidate autoComplete="off">
        {error && (
          <p className="note note-err" role="alert">
            {error}
          </p>
        )}
        <div className="form-grid">
          <label className="field">
            <span>ID</span>
            <input
              className="mono"
              name="id"
              value={id}
              onChange={(event) => setId(event.target.value.toLowerCase())}
              pattern={MODEL_ID_PATTERN}
              maxLength={32}
              required
              readOnly={Boolean(editing)}
              autoCapitalize="none"
              spellCheck={false}
              autoFocus={!editing}
            />
            <span className="hint">{editing ? "The ID cannot change." : "Lowercase letters, digits and hyphens, up to 32."}</span>
          </label>
          <label className="field">
            <span>Display name</span>
            <input name="name" value={name} onChange={(event) => setName(event.target.value)} maxLength={80} required autoFocus={Boolean(editing)} />
          </label>
          <label className="field">
            <span>Provider</span>
            <select name="provider" value={provider} onChange={(event) => changeProvider(event.target.value as Provider)}>
              {PROVIDERS.map((value) => (
                <option key={value} value={value}>
                  {PRESETS[value].label}
                </option>
              ))}
            </select>
          </label>
          <label className="field">
            <span>Base URL</span>
            <input
              className="mono"
              type="url"
              name="base_url"
              value={baseUrl}
              onChange={(event) => setBaseUrl(event.target.value)}
              maxLength={300}
              required
              spellCheck={false}
            />
          </label>
          <label className="field">
            <span>Provider model name</span>
            <input
              className="mono"
              name="model"
              value={modelName}
              onChange={(event) => setModelName(event.target.value)}
              maxLength={120}
              required
              spellCheck={false}
              placeholder={provider === "ollama" ? "qwen3:32b" : provider === "openai" ? "gpt-5" : "claude-opus-5-5"}
            />
          </label>
          <label className="field">
            <span>API key</span>
            <input
              type="password"
              name="api_key"
              value={apiKey}
              onChange={(event) => setApiKey(event.target.value)}
              autoComplete="new-password"
              maxLength={512}
              disabled={clearKey}
              placeholder={editing?.has_key ? "Leave empty to keep the stored key" : provider === "ollama" ? "Usually not needed" : ""}
            />
            <span className="hint">Write-only. It is stored on the Forge host and never shown again.</span>
          </label>
        </div>
        {editing?.has_key && (
          <label className="check">
            <input
              type="checkbox"
              checked={clearKey}
              onChange={(event) => {
                setClearKey(event.target.checked);
                if (event.target.checked) setApiKey("");
              }}
            />
            <span>Clear the stored key</span>
          </label>
        )}
        <p className="muted small">
          The Forge marks a model as cloud for Anthropic, api.openai.com or any non-private host. A cloud model receives projected evidence from
          every case that selects it and allows cloud models.
        </p>
        <div className="form-actions">
          <button type="submit" disabled={saving}>
            {saving ? "Saving…" : editing ? "Save changes" : "Add model"}
          </button>
          <button type="button" className="btn-secondary" onClick={onCancel}>
            Cancel
          </button>
        </div>
      </form>
    </Panel>
  );
}
