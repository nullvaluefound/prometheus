import { useEffect, useRef } from "react";
import { api } from "./api";
import { Header } from "./components/Header";
import { ToastProvider } from "./components/toast";
import { useResource } from "./hooks";
import { CaseView } from "./pages/CaseView";
import { CasesPage } from "./pages/Cases";
import { Dashboard } from "./pages/Dashboard";
import { ModelsPage } from "./pages/Models";
import { NotFound } from "./pages/NotFound";
import { RulesPage } from "./pages/Rules";
import { TasksPage } from "./pages/Tasks";
import { useRoute, type Route } from "./router";

function page(route: Route) {
  switch (route.name) {
    case "dashboard":
      return <Dashboard />;
    case "cases":
      return <CasesPage />;
    case "case":
      return <CaseView key={route.id} id={route.id} tab={route.tab} />;
    case "tasks":
      return <TasksPage key={route.caseFilter ?? ""} initialFilter={route.caseFilter} />;
    case "models":
      return <ModelsPage />;
    case "rules":
      return <RulesPage />;
    default:
      return <NotFound />;
  }
}

export function App() {
  const route = useRoute();
  const me = useResource((signal) => api.me({ signal }), "me");
  const mainRef = useRef<HTMLElement>(null);
  const firstRender = useRef(true);
  // Tabs inside a case change the hash but not the page, so they keep focus and scroll position.
  const pageKey = route.name === "case" ? `case:${route.id}` : route.name;

  useEffect(() => {
    if (firstRender.current) {
      firstRender.current = false;
      return;
    }
    window.scrollTo(0, 0);
    mainRef.current?.focus({ preventScroll: true });
  }, [pageKey]);

  return (
    <ToastProvider>
      <a
        className="skip-link"
        href="#main"
        onClick={(event) => {
          event.preventDefault();
          mainRef.current?.focus();
        }}
      >
        Skip to content
      </a>
      <Header route={route} me={me.data} />
      <main id="main" ref={mainRef} tabIndex={-1}>
        {page(route)}
      </main>
    </ToastProvider>
  );
}
