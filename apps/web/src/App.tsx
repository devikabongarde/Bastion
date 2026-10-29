import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { NavLink, Route, Routes, useLocation } from "react-router-dom";
import { SignInPanel, SignOutButton } from "./AuthPanel";
import { ApiError, apiGet } from "./lib/api";
import { useOverview, usePrincipal } from "./lib/hooks";
import { Empty, ErrorNotice, Icon, PageHeading, Skeleton, ToastProvider } from "./components/ui";
import Overview from "./pages/Overview";
import Assets from "./pages/Assets";
import Assessments from "./pages/Assessments";
import Findings from "./pages/Findings";
import Exceptions from "./pages/Exceptions";
import Reports from "./pages/Reports";
import Policies from "./pages/Policies";
import Schedules from "./pages/Schedules";

const navigation = [
  { href: "/", label: "Overview", icon: "overview" },
  { href: "/assets", label: "Assets", icon: "assets" },
  { href: "/assessments", label: "Assessments", icon: "scans" },
  { href: "/findings", label: "Findings", icon: "findings" },
  { href: "/exceptions", label: "Exceptions", icon: "exceptions" },
  { href: "/schedules", label: "Schedules", icon: "clock" },
  { href: "/reports", label: "Reports", icon: "reports" },
  { href: "/policies", label: "Policies", icon: "policies" },
];

function useTheme() {
  const [theme, setTheme] = useState<"dark" | "light">(() => (localStorage.getItem("bg-theme") === "light" ? "light" : "dark"));
  useEffect(() => {
    document.documentElement.dataset.theme = theme;
    localStorage.setItem("bg-theme", theme);
  }, [theme]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))] as const;
}

export default function App() {
  const principal = usePrincipal();
  const [theme, toggleTheme] = useTheme();
  const location = useLocation();
  const health = useQuery({ queryKey: ["health"], queryFn: ({ signal }) => apiGet<{ status: string }>("/health/live", signal), retry: 1, refetchInterval: 30_000 });
  const overview = useOverview(principal.isSuccess);

  if (principal.isPending) return <div className="main-content" style={{ maxWidth: 520, margin: "20vh auto" }}><Skeleton rows={3} /></div>;
  if (principal.error instanceof ApiError && principal.error.status === 401) return <SignInPanel />;
  if (principal.isError) return <div className="main-content"><PageHeading title="Overview" description="The control API is unavailable." /><ErrorNotice error={principal.error} /></div>;

  const roles = principal.data.roles;
  const current = navigation.find((n) => (n.href === "/" ? location.pathname === "/" : location.pathname.startsWith(n.href)));
  const open = overview.data?.findings_by_state.OPEN ?? 0;
  return (
    <ToastProvider>
      <div className="app-shell">
        <a className="skip-link" href="#main-content">Skip to main content</a>
        <aside className="sidebar" aria-label="Primary navigation">
          <div className="brand"><span className="brand-mark"><Icon name="shield" /></span><span>BaselineGuard<small>Configuration assurance</small></span></div>
          <p className="nav-label">Workspace</p>
          <nav className="nav-list">
            {navigation.map((item) => (
              <NavLink key={item.href} to={item.href} end={item.href === "/"} className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}>
                <Icon name={item.icon} /><span className="t">{item.label}</span>
                {item.href === "/findings" && open > 0 && <span className="nav-badge" aria-label={`${open} open findings`}>{open}</span>}
              </NavLink>
            ))}
          </nav>
          <div className="sidebar-foot">
            <div className="row"><span className={health.isSuccess ? "dot online" : "dot"} aria-hidden="true" />API {health.isSuccess ? "connected" : "unavailable"}</div>
            <p style={{ marginTop: 8 }}>Deterministic · no AI · evidence-first</p>
          </div>
        </aside>
        <div className="workspace">
          <header className="topbar">
            <span className="crumb">Workspace / <b>{current?.label ?? "Not found"}</b></span>
            <div className="top-actions">
              <button className="btn icon-btn" onClick={toggleTheme} aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}><Icon name={theme === "dark" ? "sun" : "moon"} /></button>
              <span className="user-chip"><span className="avatar" aria-hidden="true">{roles.length ? roles[0]![0]!.toUpperCase() : "?"}</span><span className="who">{roles.slice(0, 2).join(", ")}{roles.length > 2 ? ` +${roles.length - 2}` : ""}</span></span>
              <SignOutButton />
            </div>
          </header>
          <main id="main-content" className="main-content" tabIndex={-1} key={location.pathname}>
            <Routes>
              <Route path="/" element={<Overview />} />
              <Route path="/assets" element={<Assets />} />
              <Route path="/assessments" element={<Assessments />} />
              <Route path="/scans" element={<Assessments />} />
              <Route path="/findings" element={<Findings />} />
              <Route path="/exceptions" element={<Exceptions />} />
              <Route path="/schedules" element={<Schedules />} />
              <Route path="/reports" element={<Reports />} />
              <Route path="/policies" element={<Policies />} />
              <Route path="*" element={<section className="panel"><Empty icon="findings" title="Page not found">Choose a view from the primary navigation.</Empty></section>} />
            </Routes>
          </main>
          <footer className="page-footer">Configuration evidence is time-bound. Review scope, freshness and incomplete checks before acting. BaselineGuard reads and reports — it never changes target systems.</footer>
        </div>
      </div>
    </ToastProvider>
  );
}
