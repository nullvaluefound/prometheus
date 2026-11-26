import { useEffect, useId, useRef, useState, type ReactNode } from "react";
import type { CaseStatus, TaskState } from "../api";
import { decisionTone, fmtAgo, fmtTime, txt } from "../format";

type Tone = "ok" | "warn" | "err" | "info" | "muted" | "run";

export function Chip({ tone, children, dot = true }: { tone: Tone; children: ReactNode; dot?: boolean }) {
  return <span className={`chip chip-${tone}${dot ? "" : " chip-nodot"}`}>{children}</span>;
}

const TASK_TONE: Record<TaskState, Tone> = {
  queued: "info",
  running: "run",
  succeeded: "ok",
  failed: "err",
  cancelled: "muted",
};

const TASK_LABEL: Record<TaskState, string> = {
  queued: "Queued",
  running: "Running",
  succeeded: "Succeeded",
  failed: "Failed",
  cancelled: "Cancelled",
};

export function TaskChip({ state }: { state: TaskState }) {
  const tone = TASK_TONE[state] ?? "muted";
  return <Chip tone={tone}>{TASK_LABEL[state] ?? txt(state)}</Chip>;
}

const STATUS_TONE: Record<CaseStatus, Tone> = { Ready: "ok", Paused: "warn", Closed: "muted", Pending: "info" };

export function StatusChip({ status }: { status: CaseStatus }) {
  return <Chip tone={STATUS_TONE[status] ?? "muted"}>{txt(status)}</Chip>;
}

export function DecisionChip({ decision }: { decision: unknown }) {
  const label = txt(decision) || "unknown";
  return (
    <Chip tone={decisionTone(decision)} dot={false}>
      {label.replace(/_/g, " ")}
    </Chip>
  );
}

export function Badge({ tone = "muted", children, title }: { tone?: Tone; children: ReactNode; title?: string }) {
  return (
    <span className={`badge badge-${tone}`} title={title}>
      {children}
    </span>
  );
}

export function Time({ utc, relative = false }: { utc: unknown; relative?: boolean }) {
  const raw = txt(utc);
  if (!raw) return <span className="muted">—</span>;
  const exact = fmtTime(raw);
  return (
    <time dateTime={raw} title={exact} className="time">
      {relative ? fmtAgo(raw) || exact : exact}
    </time>
  );
}

export function Loading({ label = "Loading…" }: { label?: string }) {
  return (
    <p className="loading" role="status">
      <span className="spinner" aria-hidden="true" />
      {label}
    </p>
  );
}

export function Empty({ children }: { children: ReactNode }) {
  return <p className="empty">{children}</p>;
}

export function ErrorNote({ message, onRetry }: { message: string; onRetry?: () => void }) {
  return (
    <div className="note note-err" role="alert">
      <p>{message}</p>
      {onRetry && (
        <button type="button" className="btn-secondary btn-small" onClick={onRetry}>
          Try again
        </button>
      )}
    </div>
  );
}

export function Note({ tone = "info", children }: { tone?: "info" | "warn" | "err" | "ok"; children: ReactNode }) {
  return <div className={`note note-${tone}`}>{children}</div>;
}

export function Panel({
  title,
  actions,
  children,
  className = "",
  id,
}: {
  title?: ReactNode;
  actions?: ReactNode;
  children: ReactNode;
  className?: string;
  id?: string;
}) {
  const headingId = useId();
  return (
    <section className={`panel ${className}`} aria-labelledby={title ? headingId : undefined} id={id}>
      {(title || actions) && (
        <div className="panel-head">
          {title && <h2 id={headingId}>{title}</h2>}
          {actions && <div className="panel-actions">{actions}</div>}
        </div>
      )}
      {children}
    </section>
  );
}

export function RefreshButton({ onClick, busy }: { onClick: () => void; busy?: boolean }) {
  return (
    <button type="button" className="btn-secondary btn-small" onClick={onClick} disabled={busy}>
      <svg className="icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
        <path d="M13.5 8a5.5 5.5 0 1 1-1.61-3.89M13.5 2.5v3h-3" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
      </svg>
      {busy ? "Refreshing…" : "Refresh"}
    </button>
  );
}

/** A two-step button: the first click asks, the second acts. */
export function ConfirmButton({
  label,
  prompt,
  confirmLabel = "Confirm",
  onConfirm,
  disabled,
  className = "btn-secondary btn-small",
  confirmClassName = "btn-danger btn-small",
}: {
  label: string;
  prompt: string;
  confirmLabel?: string;
  onConfirm: () => Promise<unknown> | void;
  disabled?: boolean;
  className?: string;
  confirmClassName?: string;
}) {
  const [asking, setAsking] = useState(false);
  const [busy, setBusy] = useState(false);
  const confirmRef = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (asking) confirmRef.current?.focus();
  }, [asking]);
  if (!asking) {
    return (
      <button type="button" className={className} onClick={() => setAsking(true)} disabled={disabled}>
        {label}
      </button>
    );
  }
  return (
    <span className="confirm" role="group" aria-label={prompt}>
      <span className="confirm-prompt">{prompt}</span>
      <button
        ref={confirmRef}
        type="button"
        className={confirmClassName}
        disabled={busy}
        onClick={async () => {
          setBusy(true);
          try {
            await onConfirm();
          } finally {
            setBusy(false);
            setAsking(false);
          }
        }}
      >
        {busy ? "Working…" : confirmLabel}
      </button>
      <button type="button" className="btn-secondary btn-small" onClick={() => setAsking(false)} disabled={busy}>
        Cancel
      </button>
    </span>
  );
}

/** A modal built on the native dialog element, so focus trapping and Escape come from the browser. */
export function Dialog({
  open,
  title,
  onClose,
  children,
}: {
  open: boolean;
  title: string;
  onClose: () => void;
  children: ReactNode;
}) {
  const ref = useRef<HTMLDialogElement>(null);
  const headingId = useId();
  useEffect(() => {
    const dialog = ref.current;
    if (!dialog) return;
    if (open && !dialog.open) dialog.showModal();
    if (!open && dialog.open) dialog.close();
  }, [open]);
  return (
    <dialog ref={ref} className="dialog" aria-labelledby={headingId} onClose={onClose}>
      <div className="dialog-head">
        <h2 id={headingId}>{title}</h2>
        <button type="button" className="btn-icon" aria-label="Close" onClick={onClose}>
          <svg className="icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
            <path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
          </svg>
        </button>
      </div>
      {open && children}
    </dialog>
  );
}

export function Chevron({ open }: { open: boolean }) {
  return (
    <svg className={`icon chevron${open ? " chevron-open" : ""}`} viewBox="0 0 16 16" aria-hidden="true" focusable="false">
      <path d="M6 4l4 4-4 4" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

/** Validated case links only; anything else renders as plain text. */
export function CaseLink({ id, href }: { id: unknown; href: string | null }) {
  const label = txt(id);
  if (!href) return <code>{label}</code>;
  return (
    <a href={href} className="mono-link">
      {label}
    </a>
  );
}
