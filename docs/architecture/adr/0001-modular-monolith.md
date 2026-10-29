# ADR-0001: Modular monolith with separate worker processes

- **Status:** Accepted for the Phase 1 foundation
- **Context:** The PRD specifies one self-hosted control plane with API, collector, evaluator and report workers. Early microservices would add network deployment and transaction complexity before scale is measured.
- **Decision:** Keep route/domain/persistence modules in a modular monolith. Expose independent executable entry points for workers as packages become operational. Share versioned contracts.
- **Consequences:** One migration and release train is simpler. CPU-heavy or hostile parsing still runs in separately constrained processes. Modules must not import web/API routes to reach domain logic.

