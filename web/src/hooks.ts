import { useCallback, useEffect, useRef, useState } from "react";
import { ApiError, api, isAbortError, type Task, type TaskState } from "./api";

export function errorMessage(error: unknown): string {
  if (error instanceof ApiError) return error.message;
  if (error instanceof Error && error.message) return error.message;
  return "Something went wrong.";
}

export interface Resource<T> {
  data: T | undefined;
  error: string | null;
  status: number | null;
  loading: boolean;
  reload: () => void;
}

/**
 * Load data and optionally keep polling it. `poll` returns the next delay in milliseconds, or null to stop.
 * A change in `key` clears the old data; `reload()` keeps it on screen while the new copy loads.
 */
export function useResource<T>(
  load: (signal: AbortSignal) => Promise<T>,
  key: string,
  poll?: (data: T) => number | null,
): Resource<T> {
  const [state, setState] = useState<{ key: string; data?: T; error: string | null; status: number | null; loading: boolean }>(
    { key, error: null, status: null, loading: true },
  );
  const [tick, setTick] = useState(0);
  const loadRef = useRef(load);
  const pollRef = useRef(poll);
  loadRef.current = load;
  pollRef.current = poll;

  useEffect(() => {
    let alive = true;
    let timer: number | undefined;
    let controller: AbortController | undefined;
    let last: T | undefined;
    setState((previous) =>
      previous.key === key
        ? { ...previous, loading: true }
        : { key, data: undefined, error: null, status: null, loading: true },
    );

    const schedule = (delay: number | null | undefined) => {
      if (!alive || !delay) return;
      timer = window.setTimeout(() => {
        if (document.hidden) schedule(delay);
        else run();
      }, delay);
    };

    const run = () => {
      controller = new AbortController();
      loadRef.current(controller.signal).then(
        (data) => {
          if (!alive) return;
          last = data;
          setState({ key, data, error: null, status: null, loading: false });
          schedule(pollRef.current?.(data));
        },
        (error: unknown) => {
          if (!alive || isAbortError(error)) return;
          setState((previous) => ({
            ...previous,
            key,
            error: errorMessage(error),
            status: error instanceof ApiError ? error.status : null,
            loading: false,
          }));
          if (last !== undefined && !(error instanceof ApiError && error.status === 401)) {
            const next = pollRef.current?.(last);
            schedule(next ? Math.max(next, 5000) : null);
          }
        },
      );
    };

    run();
    return () => {
      alive = false;
      controller?.abort();
      window.clearTimeout(timer);
    };
  }, [key, tick]);

  const reload = useCallback(() => setTick((value) => value + 1), []);
  const current = state.key === key;
  return {
    data: current ? state.data : undefined,
    error: current ? state.error : null,
    status: current ? state.status : null,
    loading: current ? state.loading : true,
    reload,
  };
}

const TERMINAL: ReadonlySet<TaskState> = new Set(["succeeded", "failed", "cancelled"]);

export function isTerminal(state: TaskState): boolean {
  return TERMINAL.has(state);
}

export interface TrackedTask {
  task: Task | null;
  error: string | null;
}

/**
 * Poll one task until it succeeds, fails or is cancelled. `initial` shows the task from a 202 reply at once.
 * `onSettled` runs once per task id, with the final task.
 */
export function useTask(
  id: string | null,
  options: { initial?: Task | null; onSettled?: (task: Task) => void; interval?: number } = {},
): TrackedTask {
  const initial = options.initial && options.initial.id === id ? options.initial : null;
  const [state, setState] = useState<{ id: string | null; task: Task | null; error: string | null }>({
    id,
    task: initial,
    error: null,
  });
  const settledRef = useRef(options.onSettled);
  const settledFor = useRef<string | null>(null);
  const initialRef = useRef(initial);
  settledRef.current = options.onSettled;
  initialRef.current = initial;
  const interval = options.interval ?? 1500;

  useEffect(() => {
    if (!id) {
      setState({ id, task: null, error: null });
      return;
    }
    let alive = true;
    let timer: number | undefined;
    const controller = new AbortController();
    let failures = 0;
    setState((previous) => (previous.id === id ? previous : { id, task: initialRef.current, error: null }));

    const settle = (task: Task) => {
      if (settledFor.current === task.id) return;
      settledFor.current = task.id;
      settledRef.current?.(task);
    };

    const tick = async () => {
      try {
        const task = await api.task(id, { signal: controller.signal });
        if (!alive) return;
        failures = 0;
        setState({ id, task, error: null });
        if (isTerminal(task.state)) {
          settle(task);
          return;
        }
      } catch (error) {
        if (!alive || isAbortError(error)) return;
        failures += 1;
        setState((previous) => ({ ...previous, id, error: errorMessage(error) }));
        if (error instanceof ApiError && (error.status === 401 || error.status === 404)) return;
      }
      timer = window.setTimeout(tick, failures ? Math.min(interval * 2 ** failures, 15000) : interval);
    };

    const start = initialRef.current;
    if (start && isTerminal(start.state)) settle(start);
    else void tick();
    return () => {
      alive = false;
      controller.abort();
      window.clearTimeout(timer);
    };
  }, [id, interval]);

  return state.id === id ? { task: state.task, error: state.error } : { task: initial, error: null };
}

export function useDocumentTitle(title: string): void {
  useEffect(() => {
    document.title = title ? `${title} · Prometheus` : "Prometheus";
  }, [title]);
}
