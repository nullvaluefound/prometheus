import { useState } from "react";
import { api, type Lesson } from "../api";
import { useToast } from "../components/toast";
import { Badge, ConfirmButton, Empty, ErrorNote, Loading, Panel, Time } from "../components/ui";
import { isRecord, list, txt } from "../format";
import { errorMessage, useResource } from "../hooks";

/** Lessons from closed cases. Live cases propose; benchmarks adopt. Off, shadow (log only) or inject (adopted, as data). */
export function LessonsPanel() {
  const toast = useToast();
  const data = useResource((signal) => api.lessons({ signal }), "lessons");
  const rows = list<Lesson>(data.data?.lessons).filter(isRecord);

  const run = async (action: () => Promise<unknown>, done: string) => {
    try {
      await action();
      toast(done, "ok");
      data.reload();
    } catch (error) {
      toast(errorMessage(error), "err");
    }
  };

  return (
    <Panel
      title="Lessons"
      actions={
        <button type="button" className="btn-secondary btn-small" onClick={() => void run(() => api.extractLessons(), "Lessons extracted from closed cases.")}>
          Extract from closed cases
        </button>
      }
    >
      <p className="muted small">
        A lesson pairs a cue from closed cases' reviewed outcomes (failed reference checks, unsupported verdicts, rejections) with fixed advice written
        by the Forge. <strong>Shadow</strong> mode only logs which lessons a session would see. <strong>Inject</strong> shows adopted lessons to
        sessions that propose findings, as data. A lesson is adopted only on a benchmark run that lost no recall or precision.
      </p>
      {data.error && !data.data && <ErrorNote message={data.error} onRetry={data.reload} />}
      {!data.data && !data.error && <Loading label="Loading lessons…" />}
      {data.data && (
        <>
          <label className="field field-inline">
            <span>Mode</span>
            <select value={txt(data.data.mode)} onChange={(event) => void run(() => api.setLessonsMode(event.target.value), `Lessons: ${event.target.value}.`)}>
              {list<string>(data.data.modes).map((mode) => (
                <option key={mode}>{mode}</option>
              ))}
            </select>
          </label>
          {rows.length === 0 ? (
            <Empty>No lessons yet. Close cases with reviewed proposals, then extract.</Empty>
          ) : (
            <ul className="rows lead-list">
              {rows.map((lesson) => (
                <li key={lesson.id}>
                  <LessonRow lesson={lesson} onChange={run} />
                </li>
              ))}
            </ul>
          )}
        </>
      )}
    </Panel>
  );
}

function LessonRow({ lesson, onChange }: { lesson: Lesson; onChange: (action: () => Promise<unknown>, done: string) => Promise<void> }) {
  const [before, setBefore] = useState({ recall: "", precision: "" });
  const [after, setAfter] = useState({ recall: "", precision: "" });
  const cases = new Set(list<{ case: string }>(lesson.evidence).map((row) => row.case)).size;
  const adopt = () =>
    onChange(
      () =>
        api.changeLesson(lesson.id, "adopt", {
          benchmark: {
            before: { recall: Number(before.recall), precision: Number(before.precision) },
            after: { recall: Number(after.recall), precision: Number(after.precision) },
          },
        }),
      `${lesson.id} adopted.`,
    );
  return (
    <div className="lead">
      <div className="question-head">
        <code>{txt(lesson.id)}</code>
        <Badge tone={lesson.state === "adopted" ? "ok" : lesson.state === "retired" ? "muted" : "info"}>{txt(lesson.state)}</Badge>
        <code>{txt(lesson.cue)}</code>
        <span className="muted small">
          {list(lesson.evidence).length} proposals in {cases} cases · <Time utc={lesson.created_utc} relative />
        </span>
      </div>
      <p className="question-text">{txt(lesson.action)}</p>
      {lesson.state === "proposed" && (
        <div className="request-actions">
          <span className="muted small">Benchmark before</span>
          <input type="number" min={0} max={1} step={0.001} placeholder="recall" value={before.recall} onChange={(event) => setBefore({ ...before, recall: event.target.value })} />
          <input type="number" min={0} max={1} step={0.001} placeholder="precision" value={before.precision} onChange={(event) => setBefore({ ...before, precision: event.target.value })} />
          <span className="muted small">after</span>
          <input type="number" min={0} max={1} step={0.001} placeholder="recall" value={after.recall} onChange={(event) => setAfter({ ...after, recall: event.target.value })} />
          <input type="number" min={0} max={1} step={0.001} placeholder="precision" value={after.precision} onChange={(event) => setAfter({ ...after, precision: event.target.value })} />
          <button type="button" className="btn-small" onClick={() => void adopt()}>
            Adopt
          </button>
        </div>
      )}
      {lesson.state !== "retired" && (
        <div className="form-actions">
          <ConfirmButton label="Retire" prompt={`Retire ${lesson.id}?`} confirmLabel="Retire" onConfirm={() => onChange(() => api.changeLesson(lesson.id, "retire", {}), `${lesson.id} retired.`)} />
        </div>
      )}
    </div>
  );
}
