import { useEffect, useId, useRef, useState, type FormEvent, type KeyboardEvent } from "react";
import { api, type ChatMessage, type ModelConfig, type Task } from "../../api";
import { useToast } from "../../components/toast";
import { SideQuestion } from "../../components/SideQuestion";
import { ConfirmButton, DecisionChip, ErrorNote, Loading, Note, Panel, Time } from "../../components/ui";
import { MAX_CHAT_CHARS, isRecord, list, txt } from "../../format";
import { errorMessage, isTerminal, useResource, useTask } from "../../hooks";
import { caseHref } from "../../router";
import type { CaseContext } from "../CaseView";

export function ChatTab({ ctx, draft, setDraft }: { ctx: CaseContext; draft: string; setDraft: (value: string) => void }) {
  const { id, detail } = ctx;
  const toast = useToast();
  const activeRef = useRef(false);
  const chat = useResource(
    (signal) => api.chat(id, { signal }),
    `chat:${id}`,
    (data) => (data.busy || activeRef.current ? 2000 : null),
    [`chat:${id}`],
  );
  const models = useResource((signal) => api.models({ signal }), "models");
  const [pending, setPending] = useState<Task | null>(null);
  const [sending, setSending] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const tracked = useTask(pending?.id ?? null, {
    initial: pending,
    onSettled: (task) => {
      if (task.state === "failed") setError(txt(task.error) || "The model run failed.");
      chat.reload();
    },
  });
  const task = tracked.task ?? pending;
  const taskActive = task !== null && !isTerminal(task.state);
  activeRef.current = taskActive;

  const messages = list<ChatMessage>(chat.data?.messages).filter(isRecord);
  const thinking = Boolean(chat.data?.busy) || taskActive;
  const settings = detail.settings;
  const model = list<ModelConfig>(models.data?.models).find((item) => item.id === settings?.model);
  const cloudBlocked = Boolean(model?.cloud) && !settings?.allow_cloud;
  const noModel = !settings?.model;
  const blocked = noModel || cloudBlocked || ctx.inactive !== null;
  const logRef = useRef<HTMLOListElement>(null);
  const counterId = useId();
  const rulesHref = caseHref(id, "rules") ?? "#/cases";

  useEffect(() => {
    const log = logRef.current;
    if (log) log.scrollTop = log.scrollHeight;
  }, [messages.length, thinking]);

  const send = async (event?: FormEvent) => {
    event?.preventDefault();
    const message = draft.trim();
    if (!message || message.length > MAX_CHAT_CHARS || blocked || thinking || sending) return;
    setSending(true);
    setError(null);
    try {
      const reply = await api.sendChat(id, message);
      setDraft("");
      setPending(reply.task);
      chat.reload();
    } catch (failure) {
      setError(errorMessage(failure));
    } finally {
      setSending(false);
    }
  };

  const onKeyDown = (event: KeyboardEvent<HTMLTextAreaElement>) => {
    if (event.key === "Enter" && (event.ctrlKey || event.metaKey)) {
      event.preventDefault();
      void send();
    }
  };

  const clear = async () => {
    try {
      await api.clearChat(id);
      toast("Conversation cleared.", "ok");
      setPending(null);
      chat.reload();
    } catch (failure) {
      toast(errorMessage(failure), "err");
    }
  };

  return (
    <Panel
      title="Chat"
      actions={
        <ConfirmButton
          label="Clear conversation"
          prompt="Clear the whole conversation?"
          confirmLabel="Clear"
          disabled={thinking || messages.length === 0}
          onConfirm={clear}
        />
      }
    >
      <div className="stack-sm">
        {noModel && (
          <Note tone="warn">
            No model is selected for this case. <a href={rulesHref}>Pick one in the model settings on the Rules &amp; grants tab</a>.
          </Note>
        )}
        {cloudBlocked && (
          <Note tone="warn">
            The selected model is a cloud model, and this case does not allow cloud models. <a href={rulesHref}>Change the model settings</a>.
          </Note>
        )}
        {ctx.inactive && <Note tone="warn">{ctx.inactive}</Note>}
        {!noModel && (
          <p className="muted small">
            Model <code>{txt(settings?.model)}</code>
            {model && ` (${txt(model.name)}${model.cloud ? ", cloud" : ", local"})`} · role {txt(settings?.role)} ·{" "}
            {list(settings?.tools).length} tools. Every call goes through the broker. Model replies and tool output are untrusted and shown as plain text.
          </p>
        )}

        {chat.error && !chat.data && <ErrorNote message={chat.error} onRetry={chat.reload} />}
        {!chat.data && !chat.error && <Loading label="Loading the conversation…" />}
        {chat.data && (
          <ol className="chat-log" ref={logRef} aria-label="Conversation" tabIndex={0}>
            {messages.length === 0 && !thinking && <li className="chat-empty muted">No messages yet. Ask the model about this case's artifacts.</li>}
            {messages.map((message) => (
              <MessageRow key={txt(message.id)} message={message} rulesHref={rulesHref} />
            ))}
            {thinking && (
              <li className="msg msg-assistant msg-thinking">
                <span className="dots" aria-hidden="true">
                  <span />
                  <span />
                  <span />
                </span>
                {task?.state === "queued" ? "Queued behind other tasks…" : "thinking…"}
              </li>
            )}
          </ol>
        )}
        <p className="sr-only" role="status">
          {thinking ? "The model is working." : ""}
        </p>

        {error && (
          <p className="note note-err" role="alert">
            {error}
          </p>
        )}
        <form className="composer" onSubmit={send}>
          <label className="field">
            <span>Message</span>
            <textarea
              name="message"
              value={draft}
              onChange={(event) => setDraft(event.target.value.slice(0, MAX_CHAT_CHARS))}
              onKeyDown={onKeyDown}
              maxLength={MAX_CHAT_CHARS}
              rows={4}
              disabled={blocked}
              aria-describedby={counterId}
              placeholder={blocked ? "" : "Ask about an artifact by its SHA-256, a function address or a capability."}
            />
          </label>
          <div className="composer-foot">
            <span id={counterId} className={`muted small${draft.length >= MAX_CHAT_CHARS ? " over" : ""}`}>
              {draft.length.toLocaleString("en-US")} / {MAX_CHAT_CHARS.toLocaleString("en-US")} · Ctrl+Enter sends
            </span>
            <button type="submit" disabled={blocked || thinking || sending || !draft.trim()}>
              {sending ? "Sending…" : thinking ? "Working…" : "Send"}
            </button>
          </div>
        </form>
        {messages.length > 0 && <SideQuestion caseId={id} source="chat" disabled={blocked || thinking} />}
      </div>
    </Panel>
  );
}

function MessageRow({ message, rulesHref }: { message: ChatMessage; rulesHref: string }) {
  if (message.role === "user") {
    return (
      <li className="msg msg-user">
        <div className="msg-meta">
          <span className="msg-who">{txt(message.operator) || "Operator"}</span>
          <Time utc={message.utc} relative />
        </div>
        <p className="msg-text">{txt(message.text)}</p>
      </li>
    );
  }
  if (message.role === "tool") {
    const decision = txt(message.decision);
    const tone = decision === "intercepted" ? " msg-intercepted" : decision === "failed" ? " msg-failed" : "";
    return (
      <li className={`msg msg-tool${tone}`}>
        <div className="msg-meta">
          <span className="msg-who">{decision === "intercepted" ? "Intercepted tool call" : "Tool call"}</span>
          {message.tool && <code>{txt(message.tool)}</code>}
          {decision && <DecisionChip decision={decision} />}
          <Time utc={message.utc} relative />
        </div>
        <p className="msg-text">{txt(message.text)}</p>
        {decision === "intercepted" && (
          <p className="msg-reason">
            <strong>Blocked by the broker:</strong> {txt(message.reason) || "no reason recorded"}
          </p>
        )}
        {message.request && (
          <p className="msg-reason">
            A grant request for exactly this call is waiting on you. <a href={rulesHref}>Decide it on the Rules &amp; grants tab</a>.
          </p>
        )}
        {decision === "failed" && message.reason && (
          <p className="msg-reason">
            <strong>Failed:</strong> {txt(message.reason)}
          </p>
        )}
      </li>
    );
  }
  const grants = list(message.grants).length;
  return (
    <li className="msg msg-assistant">
      <div className="msg-meta">
        <span className="msg-who">{message.wrapup ? "Model wrap-up" : "Model"}</span>
        {message.model && <code>{txt(message.model)}</code>}
        <Time utc={message.utc} relative />
        {grants > 0 && (
          <span className="muted small" title="This text may quote these excerpts. It is replayed to a model only while every one of these grants is active for that model's audience.">
            drew on {grants} excerpt grant{grants === 1 ? "" : "s"}
          </span>
        )}
      </div>
      {message.wrapup && <p className="muted small">The turn used its whole tool budget, so the model wrote this summary without tools.</p>}
      <p className="msg-text">{txt(message.text)}</p>
    </li>
  );
}
