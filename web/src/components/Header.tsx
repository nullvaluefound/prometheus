import type { Me } from "../api";
import { fmtTime, txt } from "../format";
import type { Route } from "../router";

const NAV: { href: string; label: string; match: Route["name"][] }[] = [
  { href: "#/", label: "Dashboard", match: ["dashboard"] },
  { href: "#/cases", label: "Cases", match: ["cases", "case"] },
  { href: "#/tasks", label: "Tasks", match: ["tasks"] },
  { href: "#/models", label: "Models", match: ["models"] },
  { href: "#/rules", label: "Rules", match: ["rules"] },
];

export function Header({ route, me }: { route: Route; me: Me | undefined }) {
  const user = txt(me?.user);
  const expires = me ? fmtTime(me.session_expires_utc) : "";
  return (
    <header className="site-header">
      <a className="identity" href="#/">
        <span className="mark" aria-hidden="true">
          P
        </span>
        <span className="identity-text">
          <strong>Prometheus</strong>
          <span>Static malware analysis</span>
        </span>
      </a>
      <nav className="primary-nav" aria-label="Primary">
        <ul>
          {NAV.map((item) => (
            <li key={item.href}>
              <a href={item.href} aria-current={item.match.includes(route.name) ? "page" : undefined}>
                {item.label}
              </a>
            </li>
          ))}
        </ul>
      </nav>
      <div className="operator">
        {user ? (
          <a href="account" title={expires ? `Account. Session expires ${expires}` : "Account"}>
            {user}
          </a>
        ) : (
          <a href="account">Account</a>
        )}
        <form method="post" action="logout">
          <button type="submit" className="btn-link">
            Sign out
          </button>
        </form>
      </div>
    </header>
  );
}
