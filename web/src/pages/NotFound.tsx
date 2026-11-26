import { useDocumentTitle } from "../hooks";

export function NotFound() {
  useDocumentTitle("Not found");
  return (
    <>
      <h1>Not found</h1>
      <p className="muted">
        This page does not exist. <a href="#/">Back to the dashboard</a>.
      </p>
    </>
  );
}
