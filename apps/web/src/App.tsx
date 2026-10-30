import { Logo } from "./components/Logo";
import { useEffect, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { NavLink, Route, Routes, useLocation, useNavigate } from "react-router-dom";
import { SignInPanel, SignOutButton } from "./AuthPanel";
import { ApiError, apiGet } from "./lib/api";
import { useOverview, usePrincipal } from "./lib/hooks";
import { Empty, ErrorNotice, Icon, PageHeading, Skeleton, ToastProvider } from "./components/ui";
import { Toaster } from "./components/shadcn/sonner";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandGroup,
  CommandItem,
} from "./components/shadcn/command";
import Overview from "./pages/Overview";
import Assets from "./pages/Assets";
import Assessments from "./pages/Assessments";
import Findings from "./pages/Findings";
import Exceptions from "./pages/Exceptions";
import Reports from "./pages/Reports";
import Policies from "./pages/Policies";
import Schedules from "./pages/Schedules";
import Landing from "./pages/Landing";
import Docs from "./pages/Docs";
import {
  Search,
  LayoutDashboard,
  Server,
  PlayCircle,
  ShieldAlert,
  FileText,
  Layers,
  Sparkles,
  Sun,
  Moon,
} from "lucide-react";

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

function useTheme(forceLight: boolean) {
  const [theme, setTheme] = useState<"dark" | "light">(() =>
    localStorage.getItem("bg-theme") === "dark" ? "dark" : "light"
  );
  useEffect(() => {
    // Public pages (landing, docs, sign-in) are designed light-only
    document.documentElement.dataset.theme = forceLight ? "light" : theme;
    localStorage.setItem("bg-theme", theme);
  }, [theme, forceLight]);
  return [theme, () => setTheme((t) => (t === "dark" ? "light" : "dark"))] as const;
}

export default function App() {
  const principal = usePrincipal();
  const location = useLocation();
  const isPublicPage =
    ["/landing", "/docs", "/login"].includes(location.pathname) || principal.isError;
  const [theme, toggleTheme] = useTheme(isPublicPage);
  const [commandOpen, setCommandOpen] = useState(false);
  const [commandQuery, setCommandQuery] = useState("");
  const navigate = useNavigate();

  const health = useQuery({
    queryKey: ["health"],
    queryFn: ({ signal }) => apiGet<{ status: string }>("/health/live", signal),
    retry: 1,
    refetchInterval: 30_000,
  });
  const overview = useOverview(principal.isSuccess);

  // Global Command-K keyboard listener
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") {
        e.preventDefault();
        setCommandOpen((v) => !v);
      }
    };
    window.addEventListener("keydown", handleKeyDown);
    return () => window.removeEventListener("keydown", handleKeyDown);
  }, []);

  // Once signed in, leave the sign-in route for the dashboard
  useEffect(() => {
    if (principal.isSuccess && location.pathname === "/login") navigate("/", { replace: true });
  }, [principal.isSuccess, location.pathname, navigate]);

  const runCommand = (action: () => void) => {
    action();
    setCommandOpen(false);
    setCommandQuery("");
  };

  // Marketing landing page: always at /landing, and at any app route for signed-out visitors
  if (location.pathname === "/docs") {
    return <Docs />;
  }

  if (location.pathname === "/landing") {
    return <Landing onEnterApp={() => navigate(principal.isSuccess ? "/" : "/login")} />;
  }

  if (principal.isError) {
    if (location.pathname === "/login") {
      return <SignInPanel onBackToLanding={() => navigate("/")} />;
    }
    if (principal.error instanceof ApiError && principal.error.status === 401) {
      return <Landing onEnterApp={() => navigate("/login")} />;
    }
  }

  if (principal.isPending) {
    return (
      <div className="main-content" style={{ maxWidth: 520, margin: "20vh auto" }}>
        <Skeleton rows={3} />
      </div>
    );
  }

  if (principal.isError) {
    return (
      <div className="main-content">
        <PageHeading title="Overview" description="The control API is unavailable." />
        <ErrorNotice error={principal.error} />
      </div>
    );
  }

  const roles = principal.data.roles;
  const current = navigation.find((n) =>
    n.href === "/" ? location.pathname === "/" : location.pathname.startsWith(n.href)
  );
  const open = overview.data?.findings_by_state.OPEN ?? 0;

  return (
    <ToastProvider>
      <Toaster>
        <a className="skip-link" href="#main-content">Skip to main content</a>
        <div className="app-shell">
          <aside className="sidebar" aria-label="Primary navigation">
            <div className="brand" style={{ cursor: "pointer" }} onClick={() => navigate("/landing")} title="View Marketing Landing Page">
              <Logo size={26} />
            </div>
            <p className="nav-label">Workspace</p>
            <nav className="nav-list">
              {navigation.map((item) => (
                <NavLink
                  key={item.href}
                  to={item.href}
                  end={item.href === "/"}
                  className={({ isActive }) => (isActive ? "nav-link active" : "nav-link")}
                >
                  <Icon name={item.icon} /><span className="t">{item.label}</span>
                  {item.href === "/findings" && open > 0 && (
                    <span className="nav-badge" aria-label={`${open} open findings`}>{open}</span>
                  )}
                </NavLink>
              ))}
            </nav>
            <div className="sidebar-foot">
              <div className="row">
                <span className={health.isSuccess ? "dot online" : "dot"} aria-hidden="true" />
                API {health.isSuccess ? "connected" : "unavailable"}
              </div>
              <p style={{ marginTop: 8 }}>Every Control. Verified. • 100% Deterministic</p>
            </div>
          </aside>

          <div className="workspace">
            <header className="topbar">
              <span className="crumb">Bastion / <b>{location.pathname === "/landing" ? "Product Overview" : current?.label ?? "Workspace"}</b></span>
              
              <div className="top-actions">
                {/* Command-K search bar */}
                <button
                  type="button"
                  onClick={() => setCommandOpen(true)}
                  className="hidden sm:inline-flex items-center gap-2 px-3 py-1.5 rounded-full border border-[var(--line-strong)] bg-[var(--surface)] dark:bg-black/20 text-xs text-[var(--heading-soft)] hover:border-[#00D4A0] hover:text-[var(--heading)] transition-colors"
                  aria-label="Open command palette"
                >
                  <Search className="w-3.5 h-3.5" />
                  <span>Search views & actions...</span>
                  <kbd className="font-mono text-[10px] bg-[var(--surface)] dark:bg-white/10 px-1.5 py-0.5 rounded border border-[var(--line)]">
                    ⌘K
                  </kbd>
                </button>

                <button
                  className="btn sm ghost"
                  onClick={() => navigate(location.pathname === "/landing" ? "/" : "/landing")}
                >
                  {location.pathname === "/landing" ? "Return to Console" : "Product Landing"}
                </button>
                <button
                  className="btn icon-btn"
                  onClick={toggleTheme}
                  aria-label={`Switch to ${theme === "dark" ? "light" : "dark"} theme`}
                >
                  {theme === "dark" ? <Sun className="w-[18px] h-[18px]" /> : <Moon className="w-[18px] h-[18px]" />}
                </button>
                <span className="user-chip">
                  <span className="avatar" aria-hidden="true">
                    {roles.length ? roles[0]![0]!.toUpperCase() : "B"}
                  </span>
                  <span className="who">
                    {roles.slice(0, 2).join(", ")}{roles.length > 2 ? ` +${roles.length - 2}` : ""}
                  </span>
                </span>
                <SignOutButton />
              </div>
            </header>

            <main id="main-content" className="main-content" tabIndex={-1} key={location.pathname}>
              <Routes>
                <Route path="/" element={<Overview />} />
                <Route path="/landing" element={<Landing onEnterApp={() => navigate("/")} />} />
                <Route path="/assets" element={<Assets />} />
                <Route path="/assessments" element={<Assessments />} />
                <Route path="/scans" element={<Assessments />} />
                <Route path="/findings" element={<Findings />} />
                <Route path="/exceptions" element={<Exceptions />} />
                <Route path="/schedules" element={<Schedules />} />
                <Route path="/reports" element={<Reports />} />
                <Route path="/policies" element={<Policies />} />
                <Route
                  path="*"
                  element={
                    <section className="panel">
                      <Empty icon="findings" title="Page not found">
                        Choose a view from the primary navigation.
                      </Empty>
                    </section>
                  }
                />
              </Routes>
            </main>

            <footer className="page-footer">
              Bastion • Every Control. Verified. • Deterministic CIS Benchmark Configuration Assurance. Read-only forensic collection.
            </footer>
          </div>
        </div>

        {/* Global Command-K Palette (PRD 6.5) */}
        <CommandDialog open={commandOpen} onOpenChange={setCommandOpen}>
          <CommandInput
            value={commandQuery}
            onValueChange={setCommandQuery}
            placeholder="Type a command or jump to screen..."
          />
          <CommandList>
            <CommandGroup heading="Navigation">
              <CommandItem onSelect={() => runCommand(() => navigate("/"))} shortcut="G O">
                <LayoutDashboard className="w-4 h-4 text-[var(--accent-text)]" />
                <span>Overview Dashboard</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => navigate("/assets"))} shortcut="G A">
                <Server className="w-4 h-4 text-[var(--accent-text)]" />
                <span>Target Assets Inventory</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => navigate("/findings"))} shortcut="G F">
                <ShieldAlert className="w-4 h-4 text-[var(--status-fail)]" />
                <span>Verified Findings & Evidence</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => navigate("/assessments"))} shortcut="G S">
                <PlayCircle className="w-4 h-4 text-[var(--accent-text)]" />
                <span>Assessment Runs</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => navigate("/policies"))} shortcut="G P">
                <Layers className="w-4 h-4 text-[#8A79B9]" />
                <span>Policies & CIS Benchmarks</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => navigate("/reports"))} shortcut="G R">
                <FileText className="w-4 h-4 text-[var(--heading-soft)]" />
                <span>Compliance Reports (PDF/CSV)</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => navigate("/landing"))}>
                <Sparkles className="w-4 h-4 text-[var(--accent-text)]" />
                <span>Bastion Marketing Landing Page</span>
              </CommandItem>
            </CommandGroup>

            <CommandGroup heading="Actions">
              <CommandItem onSelect={() => runCommand(() => navigate("/assessments"))}>
                <PlayCircle className="w-4 h-4 text-[var(--accent-text)]" />
                <span>Launch New Fleet Assessment</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => navigate("/findings?severity=critical"))}>
                <ShieldAlert className="w-4 h-4 text-[#E53E3E]" />
                <span>Filter Critical Deviations</span>
              </CommandItem>
              <CommandItem onSelect={() => runCommand(() => toggleTheme())}>
                {theme === "dark" ? <Sun className="w-4 h-4 text-[var(--accent-text)]" /> : <Moon className="w-4 h-4 text-[var(--heading)]" />}
                <span>Toggle Theme ({theme === "dark" ? "Switch to Light" : "Switch to Dark"})</span>
              </CommandItem>
            </CommandGroup>
          </CommandList>
        </CommandDialog>
      </Toaster>
    </ToastProvider>
  );
}
