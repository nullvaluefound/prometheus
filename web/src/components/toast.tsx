import { createContext, useCallback, useContext, useRef, useState, type ReactNode } from "react";

type Tone = "info" | "ok" | "err";
interface Toast {
  id: number;
  text: string;
  tone: Tone;
}
type Push = (text: string, tone?: Tone) => void;

const ToastContext = createContext<Push>(() => undefined);

export function ToastProvider({ children }: { children: ReactNode }) {
  const [toasts, setToasts] = useState<Toast[]>([]);
  const counter = useRef(0);

  const dismiss = useCallback((id: number) => setToasts((all) => all.filter((toast) => toast.id !== id)), []);
  const push = useCallback<Push>(
    (text, tone = "info") => {
      counter.current += 1;
      const id = counter.current;
      setToasts((all) => [...all.slice(-3), { id, text: text.slice(0, 500), tone }]);
      window.setTimeout(() => dismiss(id), tone === "err" ? 10000 : 5000);
    },
    [dismiss],
  );

  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="toasts" aria-live="polite" aria-relevant="additions">
        {toasts.map((toast) => (
          <div key={toast.id} className={`toast toast-${toast.tone}`} role={toast.tone === "err" ? "alert" : "status"}>
            <p>{toast.text}</p>
            <button type="button" className="btn-icon" aria-label="Dismiss notification" onClick={() => dismiss(toast.id)}>
              <svg className="icon" viewBox="0 0 16 16" aria-hidden="true" focusable="false">
                <path d="M4 4l8 8M12 4l-8 8" fill="none" stroke="currentColor" strokeWidth="1.6" strokeLinecap="round" />
              </svg>
            </button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

export function useToast(): Push {
  return useContext(ToastContext);
}
