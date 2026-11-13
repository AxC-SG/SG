# UI 2.0 improvements

Updated November 13, 2026. This folder records the visible UI review, delivery decisions and implementation through Stage 6. Architecture, APIs, data definitions, persistence, scalability and instrumentation are tracked in the separate non-UI ledger.

| Read in order | Purpose |
|---|---|
| [Application UI review](application-ui-architecture-review-2026-10-28.md) | UI findings and evidence; retained filename for existing references |
| [UI implementation plan](UI_IMPLEMENTATION_PLAN.md) | Ranked UI backlog, shared-root ownership, adoption sequence and acceptance |
| [Shared UI proposal](SHARED_UI_PROPOSAL.md) | Concrete shell/control proposal, exact candidate visual values, alternatives and decision record |
| [Workbench UI journey](CVE_WORKBENCH_UI_JOURNEY.md) | Overview → investigation → applicability → impacted assets → fixes → notification drafts; transitions and UI checks |
| [Page review register](application-page-review-register-2026-10-28.md) | All page modules and subviews mapped to UI work items; adoption checklist |
| [Exposure UI review](exposure-shell-review-2026-10-28.md) | Specific feedback against the supplied dashboard reference |
| [Non-UI improvement ledger](NON_UI_IMPROVEMENTS_LEDGER.md) | Separate candidate work for data/API/domain correctness, persistence and frontend architecture; dependencies only in the UI docs |

The standing [UI development standard](../ui-development-standard.md) and [styles/rollback guide](../ui2-styles-and-rollback.md) are canonical in `prototype-app/docs/`. The two same-named files here are location pointers, not duplicate standards.

The implementation plan records the selected Intelligence navigation and six peer Workbench tabs, the changes integrated at each stage and the remaining acceptance items. The full Workbench exit guard depends on the router work tracked as N07a.

The October 30 [backend wiring checks](../ui2-backend-wiring-fixes-2026-10-30.md) and [screenshot comparison](../ui2-ci-visual-repair-2026-10-30.md) record results for their tested candidates. See the plan for remaining designer and QA acceptance and the [migration record](../CURRENT_STATE.md) for release qualification.
