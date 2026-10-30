# Bastion Web Console & Landing Page

> **Every Control. Verified.**  
> Self-hosted, offline-capable compliance and hardening auditor inspired by Semgrep's clean, authoritative, evidence-first engineering aesthetic.

---

## 1. Design Tokens & Theme Specification

Bastion enforces a consistent global design system defined in [`src/theme.css`](file:///d:/mini_proj_hack/apps/web/src/theme.css). Both the marketing landing page and the enterprise console inherit these design tokens:

| Token | Hex / Value | Purpose |
|---|---|---|
| `--bg` | `#F7F7F5` | Off-white calm page background |
| `--surface` | `#FFFFFF` | Card surfaces and elevated containers |
| `--forest` | `#2F3E39` | Authoritative forest green (announcement bar, footer, dark containers) |
| `--accent` | `#1FCB9B` | Mint green primary action color |
| `--accent-hover` | `#18A27C` | Darker mint shade on button hover |
| `--mint-tint` | `#DCEEE5` | Rounded feature container tint (Panel 1) |
| `--peach-tint` | `#FDECE3` | High-visibility finding container tint (Panel 2) |
| `--lavender-tint` | `#EAE8F7` | Replayable evidence container tint (Panel 3) |
| `--heading` | `#2E4A40` | Deep forest heading text |
| `--heading-soft` | `#5B7B6C` | Muted subtitle and secondary text |
| `--body` | `#555555` | Body copy |

### Typography & Radii
- **Primary Body & Headings**: Inter
- **Hashes, IDs, Commands, Eyebrows**: Geist Mono (`font-mono`)
- **Interactive Radii**: `rounded-full` (pills for inputs, buttons, status badges)
- **Container Radii**: `rounded-[28px]` or `rounded-[32px]` for cards, modals, and sheets

---

## 2. Shadcn Primitives Catalog

All UI primitives are componentized in [`src/components/shadcn/`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/):

| Component | Source File | Description |
|---|---|---|
| **Button** | [`button.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/button.tsx) | Pill-shaped action buttons (`primary`, `outline`, `ghost`, `danger`) |
| **Input** | [`input.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/input.tsx) | Pill-shaped input with forest focus rings |
| **Card** | [`card.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/card.tsx) | 28px rounded containers with `mint`, `peach`, `lavender`, and standard variants |
| **StatusBadge** | [`status-badge.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/status-badge.tsx) | **WCAG 2.2 AA compliant**: always pairs text + icon (never color alone) |
| **Table** | [`table.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/table.tsx) | Monospaced table headers, soft row dividers, and hover feedback |
| **Tabs** | [`tabs.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/tabs.tsx) | Pill tab switcher with context provider |
| **Dialog** | [`dialog.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/dialog.tsx) | Accessible backdrop modal with keyboard escape trap |
| **Sheet** | [`sheet.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/sheet.tsx) | Sliding drawer for 3-column finding details and asset inspectors |
| **Command** | [`command.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/command.tsx) | Global `⌘K` / `Ctrl+K` quick navigation and action switcher |
| **DropdownMenu** | [`dropdown-menu.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/dropdown-menu.tsx) | Contextual action menus with outside-click dismissal |
| **Accordion** | [`accordion.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/accordion.tsx) | Collapsible sections with smooth Chevron rotation |
| **Tooltip** | [`tooltip.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/tooltip.tsx) | Hover/focus tooltip with subtle directional arrow |
| **Sonner / Toast** | [`sonner.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/sonner.tsx) | Non-intrusive bottom-right toast notifications |
| **Skeleton** | [`skeleton.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/skeleton.tsx) | Low-contrast pulsing loading placeholders |
| **Breadcrumb** | [`breadcrumb.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/breadcrumb.tsx) | Breadcrumb trail with chevron separators |
| **Progress** | [`progress.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/shadcn/progress.tsx) | Smooth animated progress bar |

---

## 3. React Bits Animation Components

Polish animations are encapsulated in [`src/components/reactbits/`](file:///d:/mini_proj_hack/apps/web/src/components/reactbits/):

| Component | Source File | Effect |
|---|---|---|
| **SplitText** | [`SplitText.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/reactbits/SplitText.tsx) | Staggered character reveal in hero ("Every Control." / "Verified.") |
| **ShinyText** | [`ShinyText.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/reactbits/ShinyText.tsx) | Continuous shimmer sweep in top announcement bar |
| **CountUp** | [`CountUp.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/reactbits/CountUp.tsx) | Cubic-eased numbers on scroll entry with decimal precision support |
| **SpotlightCard**| [`SpotlightCard.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/reactbits/SpotlightCard.tsx) | Subtle cursor-tracking radial mint glow across "Why Bastion" cards |
| **Magnet** | [`Magnet.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/reactbits/Magnet.tsx) | Gentle physics attraction for primary CTA buttons |
| **FadeContent** | [`FadeContent.tsx`](file:///d:/mini_proj_hack/apps/web/src/components/reactbits/FadeContent.tsx) | Subtle fade-up intersection observer supporting reduced-motion |

---

## 4. Scroll Choreography & Smooth Motion

Smooth scrolling is powered by **Lenis** synchronized with **GSAP ScrollTrigger**:
```ts
// Lenis + GSAP sync pattern in Landing.tsx
const lenis = new Lenis({ duration: 1.2, smoothWheel: true });
lenis.on('scroll', ScrollTrigger.update);
gsap.ticker.add((time) => lenis.raf(time * 1000));
gsap.ticker.lagSmoothing(0);
```
- **Accessibility Guarantee**: Respects `prefers-reduced-motion` (turns off translation, retains soft opacity fades).

---

## 5. Status Badges & WCAG 2.2 AA Compliance

Bastion strictly enforces **Icon + Text pairing** so color is never the only signal:

```tsx
<StatusBadge status="PASS" count={90} />           // Mint Checkmark + "PASS (90)"
<StatusBadge status="FAIL" count={18} />           // Orange X + "FAIL (18)"
<StatusBadge status="UNKNOWN" count={8} />         // Slate ? + "UNKNOWN (8)"
<StatusBadge status="ERROR" count={2} />           // Red Alert Triangle + "ERROR (2)"
<StatusBadge status="MANUAL_REQUIRED" count={2} /> // Lavender User + "MANUAL (2)"
<StatusBadge status="NOT_APPLICABLE" count={14} /> // Gray Dash + "N/A (14)"
```

---

## 6. PRD 6.5 Console Screen Implementations

1. **Overview Dashboard** ([`src/pages/Overview.tsx`](file:///d:/mini_proj_hack/apps/web/src/pages/Overview.tsx)):
   - Dual rings: Evaluated Compliance (`pass / (pass + fail)`) and Assessment Completeness (`(pass + fail) / total`).
   - Zero denominator defense: Displays `"No assessable results"` when total is 0.
   - Stacked horizontal status distribution bar with count badges.
   - Freshness indicators: Fresh (&lt;24h), Stale (&gt;7d), Never, and Unreachable.
   - Demo mode switcher to toggle between live backend API and the rich PRD benchmark dataset.

2. **Target Assets Inventory** ([`src/pages/Assets.tsx`](file:///d:/mini_proj_hack/apps/web/src/pages/Assets.tsx)):
   - Heterogeneous fleet table (Linux, Windows Server, Cisco IOS XE, FortiGate firewalls).
   - Capability pills (`ssh_exec`, `registry_read`, `winrm`, `file_read`).
   - Host key fingerprint trust pinning (`SHA-256`).
   - Bulk CSV import with deterministic dry-run preview before commit.

3. **Findings & Evidence** ([`src/pages/Findings.tsx`](file:///d:/mini_proj_hack/apps/web/src/pages/Findings.tsx)):
   - Filterable deviations table by severity, state, asset, and search query.
   - **3-Column Comparison Sheet**:
     * Column 1: `Expected (Source CIS Benchmark)`
     * Column 2: `Expected (Custom Policy Override)`
     * Column 3: `Actual Observed Value`
   - Monospaced raw evidence excerpt with a 1-click **Copy Evidence** button.
   - Reviewed remediation plan with step-by-step commands, impact note, and a **Copy Fix** button.
   - Dual-custody risk exception request workflow.

4. **Global Command-K Palette** ([`src/App.tsx`](file:///d:/mini_proj_hack/apps/web/src/App.tsx)):
   - Triggerable anywhere via `⌘K` or `Ctrl+K`.
   - Rapid jump between Overview, Assets, Findings, Policies, Reports, and Marketing Landing.
   - One-click Light / Dark mode toggle and instant scan launch.

---

## 7. How to Edit Copy or Add New Controls

- **Product Copy & Claims**: All landing page text is in [`src/pages/Landing.tsx`](file:///d:/mini_proj_hack/apps/web/src/pages/Landing.tsx).  
  *Rule*: Keep language calm, factual, and evidence-first. Never add AI/ML or LLM claims.
- **Mock Benchmarks & Targets**: Defined in [`src/lib/mockData.ts`](file:///d:/mini_proj_hack/apps/web/src/lib/mockData.ts) (`MOCK_OVERVIEW`, `MOCK_ASSETS`, `MOCK_FINDINGS`).
- **Development Server**:
  ```powershell
  corepack pnpm --filter @baselineguard/web dev
  ```
- **Build & Verification**:
  ```powershell
  corepack pnpm --filter @baselineguard/web build
  corepack pnpm --filter @baselineguard/web test
  ```

