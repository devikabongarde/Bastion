# Bastion documentation

Bastion (internal package name `baselineguard`) is a deterministic, read-only configuration compliance auditor. Each page below was written from the current code. Where a page and the code disagree, the code wins.

## Architecture

| Document | Description |
|---|---|
| [architecture/overview.md](architecture/overview.md) | Components, end-to-end scan flow, embedded workers, multi-tenancy/RLS, authentication, audit hash chain |
| [architecture/data-model.md](architecture/data-model.md) | Tables, relationships, state machines (jobs, scan targets, findings, exceptions), migration list |
| [architecture/repository-map.md](architecture/repository-map.md) | What each directory of the repository contains |
| [architecture/threat-model.md](architecture/threat-model.md) | Assets, trust boundaries, threats and the controls that exist in code, known gaps |
| [architecture/adr/0001-modular-monolith.md](architecture/adr/0001-modular-monolith.md) | ADR: modular monolith with separate worker processes |
| [architecture/adr/0002-postgres-tenancy-and-rls.md](architecture/adr/0002-postgres-tenancy-and-rls.md) | ADR: PostgreSQL tenant context and forced row-level security |
| [architecture/adr/0003-phase0-external-gates.md](architecture/adr/0003-phase0-external-gates.md) | ADR: external gates (vendor labs, content rights) remain open |

## Reference

| Document | Description |
|---|---|
| [api/current-api.md](api/current-api.md) | Every HTTP route: method, path, required role, purpose |
| [adapters/compatibility.md](adapters/compatibility.md) | Adapters, exact read-only commands, site-scope checks, host-key pinning, collection error codes |
| [content-provenance/README.md](content-provenance/README.md) | Rule packs, control counts, how packs are built and registered, provenance rules |

## Development

| Document | Description |
|---|---|
| [development/local-setup.md](development/local-setup.md) | Prerequisites, `.env` variables, PostgreSQL, migrations, seeding, running the API, web console and mock devices |
| [development/verification.md](development/verification.md) | How to run ruff, pyright, pytest (unit/integration), web typecheck/tests/build, Playwright, and what CI runs |
| [development/project-status.md](development/project-status.md) | What works today, known defects and limitations, what is not implemented |
| [testing/ui-test-guide.md](testing/ui-test-guide.md) | Manual click-through test plan for the console |

## Operations

| Document | Description |
|---|---|
| [runbooks/demo-day.md](runbooks/demo-day.md) | Startup sequence, pre-demo checklist, demo flow, recovery |
| [runbooks/ubuntu-lab-onboarding.md](runbooks/ubuntu-lab-onboarding.md) | Onboarding real Ubuntu machines on a lab network, with troubleshooting by error code |
| [runbooks/windows-lab-onboarding.md](runbooks/windows-lab-onboarding.md) | Onboarding a remote Windows 10/11 PC over the built-in OpenSSH Server |
| [user-guide/first-run.md](user-guide/first-run.md) | Landing page → sign-in → console tour and first tasks |

`USER_MANUAL.md` in the repository root is the presenter's manual and Q&A sheet. It links back to these documents.
