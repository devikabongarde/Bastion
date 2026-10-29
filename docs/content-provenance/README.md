# Rule content provenance

## Content shipped in this repository

`content/original/phase1-linux.yaml` is a small, original Ubuntu 22.04 demonstration pack. It is labeled organizational, contains no CIS recommendation text or mappings, and is not a CIS Benchmark implementation. Its presence does not establish that its reader facts are currently collected by a complete production scan pipeline. Review its schema and fixtures before use.

The JSON Schema at `content/schemas/rule-pack.schema.json` defines the declarative pack format. `packages/rule_engine` validates the pack structure and bounds rule expression depth/node count; rules cannot submit arbitrary shell commands or executable code. The pack schema's fixture expectations should be replayed in tests before any change is accepted.

## Provenance required before adding content

Every pack release must preserve a manifest containing at minimum:

- stable pack id, semantic version, exact content digest, publisher and license;
- target family, version range, roles, and engine compatibility;
- source benchmark publisher/product/version/profile only when applicable;
- recommendation-level mapping, exact source rights/reference, reviewer and review date for mapped rules;
- original vs. vendor-guidance vs. mapped origin for every control;
- change log, applicability explanation, required facts, expected typed value, remediation procedure, evidence fields and pass/fail/unknown fixtures;
- source artifact identity and hash retained in the private provenance record if redistribution is not allowed.

Do not copy CIS text, mappings, benchmark identifiers or derived recommendation content into the repository or a distributable artifact until its license and redistribution rights have been reviewed. Keep private organization content separate from the public original pack. A license label alone is not legal review.

## Review and release sequence

1. Resolve source rights and document the permitted use.
2. Freeze the exact product/build/profile and collection fields in a compatibility record.
3. Author the smallest deterministic rule using only supported facts and bounded operators.
4. Add fixtures for each result status, missing evidence, unsupported applicability, conflicts and malformed evidence.
5. Have a second reviewer confirm applicability, severity, expected value, remediation safety and provenance.
6. Replay all pack fixtures, calculate the canonical semantic digest, and review coverage/exclusions.
7. Publish a new immutable version. Never mutate a published pack or rewrite an existing audit's provenance.
8. Canary the new version, inspect changed results, then promote or revoke while keeping old run records reproducible.

No AI/ML or external paid service participates in content authoring, evaluation or release decisions.
