# Step 5 decision package: retire the legacy (UI 1) presentation?

**Candidate:** app source at `6cba0983` (Step 4 tip). Later Step 5 commits change only files under `Working Knowledge/`.
**Evidence:** `CLEANUP_PROGRESS.json`, unit S5 (gates) and unit S4 (gate run on the candidate).

## What the decision means

A yes lets Step 6 start: removing the legacy styles one family at a time, then the version switch. After that, rolling back to UI 1 means **serving the frozen UI 1 build**, not rebuilding old code. A yes does **not** approve the final artifact. Step 8 qualifies that separately, and release needs its own approval.

## Evidence

| Gate | Result |
|---|---|
| Live journeys on the candidate | ✅ 250/250 passed, 2 skipped (outbound ServiceNow delivery is not allowed; the fixture journey covers it) |
| Fixture journeys | ✅ UI 2 737/737; UI 1 703/737, all 34 failures in the reviewed baseline |
| Visual and affected (Playwright container) | ✅ 280/280 screenshots; 0 new axe violations |
| Responsive sweep: 390/768/1280/1440, both themes, both versions | ✅ 0 page errors. 2 known UI 2 overflows at 768 (`/configurations/sla`, `/configurations/suppress`) |
| Backend `mvn -Ppostgres-it verify` | ✅ 1308 unit + 496 integration tests, 0 failed; coverage met; SpotBugs 0 |
| Bundle vs Step 0 | ✅ CSS +183 bytes raw / +44 gzip; JS unchanged |
| Runtime vs Step 0 | ✅ no measurable difference (median of 7 cold loads; A/A check) |
| Frozen UI 1 build | ✅ `checkpoints/UI1-frozen-a3f1d1db.tar.gz`, sha256 `f040137d…1a707`, 86 files in the manifest, reproducible |
| Rollback rehearsal with the frozen build on current local data | ✅ 20/20: sign-in, 14 pages, no server errors, nothing left the machine |
| CI on the exact commit | ✅ PR #24 (Step 4, candidate `a3f1d1db`): all 13 jobs passed, merged as `47ab4728`. ⏳ Draft PR #25 for the Step 5 records |
| **Keyboard focus** | ❌ **UI 2 hides the keyboard focus ring** on every `.btn-primary`/`.btn-secondary`, the tenant pill and the active nav item (25 element kinds; UI 1 misses 5). Cause: UI 2 sets `box-shadow` on these at higher specificity than the global `:focus-visible` ring in `base.css`. Pre-existing since the UI 2 import, not from Step 4 |
| Accessibility review | ❌ blocked by the focus issue. Also still open: the logged extra serious axe findings (80 color-contrast, 12 scrollable-region-focusable) and the mouse-only declared-resource rows |
| 200% zoom | Automated approximation: UI 2 is clean apart from `/demo/blog` (+8px, public page); UI 1 overflows on 7 pages. **A real-browser check is still needed** |
| Human visual approval and keyboard review | 👤 open |
| Authenticated staging | ❌ open: no staging environment exists |

## What you need to decide

1. **Fix the keyboard focus ring before retiring UI 1?** Recommended: yes. It's a small UI 2 change: a `:focus-visible` ring in `primitives.css`/`shell.css` that keeps the existing shadow. Visual baselines would change, through `e2e:update` with inspected diffs.
2. **Do your human review:** visual approval, keyboard use, and a real 200% browser zoom on a few key pages (Findings, CVE workbench, Inventory, Connect, Platform tenants).
3. **Accept that the staging gate stays open**, since there's no environment, or name a staging target.
4. **Write the decision**, for example: "I approve ending the legacy presentation and rollback by rebuild; rollback is by the frozen artifact `UI1-frozen-a3f1d1db` (sha256 `f040137d4956b5bcc68133b89b2eb1f28136a456561a76f7236200352c81a707`)." Add any conditions, such as "after the focus fix".
5. **Merge draft PR #25** (Step 5 records) after the decision, with a merge commit.
