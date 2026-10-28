# UI 2.0 migration record

Updated October 28, 2026. The application migration is complete. This folder is a compact historical handoff and rollback record; new screen development belongs in the live app and follows [the UI development standard](../../docs/ui-development-standard.md).

The separate [UI 2.0 improvement package](<UI 2.0 improvements/README.md>) contains the current UI-elements review and proposed adoption plan. Its non-UI improvement ledger is independent of the migration history below; neither proposals nor documentation completion certify new implementation or release qualification.

| Question | Retained record |
|---|---|
| What was the previous state? | [PREVIOUS_STATE.md](PREVIOUS_STATE.md), with the verified P0 source archive and frozen UI 1 build in `checkpoints/` |
| What plan was implemented? | [IMPLEMENTATION_PLAN.md](IMPLEMENTATION_PLAN.md) for the original phases; [UI2-Final-Implementation-Plan.md](UI2-Final-Implementation-Plan.md) for qualification, cleanup and legacy retirement |
| What is the current state? | [CURRENT_STATE.md](CURRENT_STATE.md), including completed code work, later fixes, cleanup decisions and evidence still outstanding |
| What evidence/decisions must remain? | `IMPLEMENTATION_PROGRESS.json` and `CLEANUP_PROGRESS.json` retain dated per-phase results, retirement decisions/waivers, measurements and limitations |
| How is previous code/build integrity checked? | Two archives, each with its checksum and per-file manifest; commands in [styles and rollback](../../docs/ui2-styles-and-rollback.md#retained-archives) |
| What tools are still needed? | [tools/README.md](tools/README.md): final qualification, style/state comparison, keyboard/zoom aid, performance and frozen-artifact rehearsal |

The plans and ledgers are **historical**, not instructions to restart migration. Their branch names, personal paths, deleted-file references, baseline counts and pending statuses describe their recorded time. `UI2-Final-Implementation-Plan.md` is retained byte-for-byte from the user's supplied plan; the duplicate `CLEANUP_PLAN.md` was removed. `CURRENT_STATE.md` and the live docs govern current development. Historical evidence does not certify a later branch tip.

The standalone mock/reference project (including its generated dependencies/build output), obsolete start/continue prompts, intermediate family maps, route checklists, duplicated phase captures/logs and obsolete diagnostic wrappers have been removed. Recover historical tracked material from Git at `eedc8a0864cadf7c0cd0e55ec733f4637ff6622a` if investigation needs it; don't reintroduce it as active app guidance. Active route fixtures, visual/axe/journey baselines and CI remain in `frontend/e2e/` and `.github/workflows/`.

Keep the archives and decision/evidence ledgers until the release owner closes the rollback window. Final release qualification and deployment authorization remain separate from source migration completion.
