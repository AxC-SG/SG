# UI 2.0 improvements

Updated October 28, 2026. The feedback and delivery plan in this folder are restricted to visible UI elements and interactions. Architecture, APIs, data definitions, persistence, scalability and instrumentation are tracked separately.

| Read in order | Purpose |
|---|---|
| [Application UI review](application-ui-architecture-review-2026-10-28.md) | UI findings and evidence; retained filename for existing references |
| [UI implementation plan](UI_IMPLEMENTATION_PLAN.md) | Ranked UI backlog, shared-root ownership, adoption sequence and acceptance |
| [Shared UI proposal](SHARED_UI_PROPOSAL.md) | Concrete shell/control proposal, exact candidate visual values, alternatives and decision record |
| [Workbench UI journey](CVE_WORKBENCH_UI_JOURNEY.md) | Overview → investigation → applicability → impacted assets → fixes → notification drafts; transitions and UI checks |
| [Page review register](application-page-review-register-2026-10-28.md) | All page modules and subviews mapped to UI work items; adoption checklist |
| [Exposure UI review](exposure-shell-review-2026-10-28.md) | Specific feedback against the supplied dashboard reference |
| [Non-UI improvement ledger](NON_UI_IMPROVEMENTS_LEDGER.md) | Separate candidate work for data/API/domain correctness, persistence and frontend architecture; dependencies only in the UI docs |

The standing [UI development standard](../../../docs/ui-development-standard.md) and [styles/rollback guide](../../../docs/ui2-styles-and-rollback.md) are canonical in `prototype-app/docs/`. The two same-named files here are location pointers, not duplicate standards.

Scope decision: the user requested an application review, document updates following feedback, and then explicitly restricted feedback to UI elements with a separate non-UI ledger. Those requests authorize this documentation revision. The user subsequently selected separate Intelligence navigation and six peer Workbench tabs; those selections are recorded in the plan/proposal. These requests do not record implementation or expand product capabilities. No application code is changed.

Source inspection and saved screenshots support the diagnosis. Fresh browser, visual, accessibility and live persistence evidence is pending; see the evidence gate in the UI plan. All completion boxes describe future verification unless explicitly marked as documentation verification.

Latest plan revision incorporates early state primitives, named breakpoint consolidation, independent coarse-pointer targets, explicit draft/URL/exit contracts, table override/reset compatibility, in-place modal confirmation, single-header assertions, per-slice effort and bounded visual/accessibility verification. The supporting router migration is tracked separately as N07a; full UI exit protection cannot be marked complete before it. No application code or snapshots were changed by this revision.
