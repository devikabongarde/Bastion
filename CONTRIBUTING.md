# Contributing

Read [PRD.md](./PRD.md) before changing architecture, schemas, rule semantics, security behavior, or compatibility claims. The PRD is binding.

- Keep device readers fixed, read-only, bounded, and version tested.
- Do not commit secrets, production evidence, appliance images, or benchmark content without documented distribution rights.
- Add synthetic fixtures and tests for behavior changes; never turn missing evidence into a pass.
- Keep published schemas and migrations backward compatible when possible; use expand/migrate/contract changes.
- Run Python and frontend checks listed in the README.

