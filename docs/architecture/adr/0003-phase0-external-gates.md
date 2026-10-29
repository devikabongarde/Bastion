# ADR-0003: Phase 0 external gates remain open

- **Status:** Open, recorded 29 October 2026
- **Context:** Phase 0 requires exact build/role matrix and authorized vendor labs, rights review for benchmark content, real transport spikes, and user validation.
- **Observed:** The repository contained only `PRD.md`. The workspace has no vendor credentials/lab endpoints or content-rights artifacts. The PRD's planned build/role matrix is recorded as `planned` in `content/compatibility.yaml`.
- **Decision:** Do not fabricate lab output, approval, user feedback, or a CIS license. Implement platform-neutral interfaces and original synthetic fixtures; block claims of live support and CIS-mapped content pending the required evidence.
- **Required follow-up:** An authorized platform owner records exact builds and non-production credentials out of band; a content/legal owner records rights references. Then run the live read-only spikes and update compatibility records with evidence and reviewer.

