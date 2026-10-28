# Exposure dashboard and shared shell — UI review

Updated October 28, 2026. Scope: the supplied reference, Exposure's visible UI elements and shared shell interactions. Data definitions, API behavior and score/aggregation decisions are separately tracked in [the non-UI ledger](NON_UI_IMPROVEMENTS_LEDGER.md). Use [the UI plan](UI_IMPLEMENTATION_PLAN.md) for rank and acceptance and [the shared proposal](SHARED_UI_PROPOSAL.md) for exact candidate values.

Evidence: implemented markup/styles and saved desktop/mobile fixture screenshots, plus the supplied image. No current live walkthrough or fresh visual/axe result is claimed. Text inside the image is reference content, not separate instructions. The user's six requests control the design direction, including Policies outside Assets even though the reference places it inside.

## The six requested UI improvements

| Request | UI recommendation | Plan mapping |
|---|---|---|
| Appropriate icons | Consistent 18px primary-nav icons; 16px KPI icons in subtle semantic containers; asset-type icons in lists. Use installed lucide-react exports after checking availability; hide decorative glyphs from assistive technology. | U03/U11 |
| Remediation and Assets sections | Visible non-clickable headings, deliberate spacing and no empty groups after access filtering. | U03 |
| Exposure outside sections | Standalone first destination above both groups, with clear current-route treatment. | U03 |
| AI Policies → Policies, outside Assets | Standalone peer after the asset group. Keep accurate AI-specific supporting description and current entitlement; no capability expansion implied. | U03 |
| Tight, compact Grid Exposure | Constrain matrix to the left panel, shorten host label, use equal readable severity columns and a narrow total column. | U02/U11 |
| Better widget placement | Put Grid Exposure beside Remediation Progress, action panels next and funnel lower. | U11 |

## Proposed wide-desktop composition

```text
Shared top bar: workspace context                         theme / account
Exposure Dashboard • freshness
[Critical] [Open] [Impacted CVEs] [KEV] [precise action label] [EOL]
[Grid Exposure                              7/12] [Remediation Progress 5/12]
[Critical CVEs Requiring Action              6/12] [Attention items       6/12]
[Most Exposed Software                      6/12] [Exposed Assets        6/12]
[CVE Exposure Funnel / intelligence context                            12/12]
```

These retain all existing widgets. Consider one compact “Needs action now” strip using already-supported attention items **instead of duplicating** the same insights in several places. A changed-since-last-visit strip is not included without the separate N11 data/capability decision.

The user selected the [proposal](SHARED_UI_PROPOSAL.md)'s separate Intelligence group and flatter Findings destinations. Retain those selections and the six original requests; Workbench routes highlight Vulnerability Repository. Do not add a nonfunctional Review hub or Reference controls overlay.

## Element specifications

- Use 24px desktop content gutters, 16px panel gaps/padding, 22px route title, 16px panel headings and readable captions. Stack captions below titles with a separate right-aligned relevant action.
- KPI label + icon, value and caption use a consistent order. Initial wide reference card height is 112px minimum, growing for readable content rather than clipping essential text. Six columns at ≥1200px, three at 640–1199px (including tablet portrait), and two below 640px. Grid/progress is side by side only at ≥1200px.
- Grid cell controls start at 32px height, 40px row pitch and 4px cell gap; use 44px interactive row pitch when any-pointer:coarse matches, including wide tablets; width alone does not imply touch. Keep values readable and tabular; do not scale down the entire page to fit the reference image.
- Domain column uses concise names in a stable order. Equal severity columns and right-aligned totals support scanning. Severity hue is consistent; zeros are neutral. Any tint-intensity meaning must have a short explanation.
- Nonzero cell actions have contextual accessible names, such as “Hosts, Critical, 31 open findings,” focus and an equivalent readable value. Supported totals may link using the same scope. Backend population/filter work is N03.
- Show all currently supported rows without unnecessary vertical scroll. Use bounded/sticky headers only when row count needs it. On narrow screens keep the label and numeric columns readable inside intentional scrolling.
- Remediation uses a compact labelled status presentation with text values. A stacked 100% chart depends on N03's non-overlapping population contract; do not infer that from the mock. Avoid a score ring until its usefulness and meaning are decided under N03/N11.
- Do not force lower cards to equal excessive heights. Show the highest-priority attention preview with an accessible expansion or meaningful destination for the rest. Keep short lists compact.
- Use human-readable asset names, secondary technical identifiers and real asset icons. Full names/IDs remain copyable and accessible when truncated.

## Label, state and interaction feedback

“Critical Findings” should read as critical severity; a risk-threshold figure needs an explicit high-risk label. Replace vague “Needs Attention” with the verified population, e.g. “Impacted CVEs without findings” when N03 confirms that definition. Keep CVEs, findings, assets and components visibly distinct.

Unavailable metrics show an explanation and `—`, successful zero shows `0`, and refresh failure retains existing data with a warning. Each widget has its own loading/error/retry/empty state. A missing source must not produce a healthy score or clean-posture message. Freshness copy describes whether it is fetch time or data time; source/time semantics belong to N12.

The reference's illustrative values are not targets. Reconciliation is recorded under N03. Its fifth AI Assets row depends on N10; the UI must not fabricate it. Current infrastructure-only coverage can be stated in supporting copy.

Consolidate the duplicate account/settings entry into an understandable account control while keeping existing account actions reachable. Separate shell navigation and disclosure buttons, label icon-only controls, expose current/expanded state and verify mobile drawer focus/Escape/close/return behavior.

## Acceptance

U11 adopts U01–U06 shared contracts after the reference slice, while targeted broken-state/path repairs U01/U07/U08 proceed independently. Inspect 1440/1280/768/390px, light/dark, long names/large values, valid zero, partial and failed data, keyboard and 200% zoom. Confirm matrix readability, compact action panels, nonclipped captions and reachable drill-downs. Record actual candidate/evidence; no new pass or release is inferred from this review.
