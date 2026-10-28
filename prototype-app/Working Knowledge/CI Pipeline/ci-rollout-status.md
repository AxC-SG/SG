# CI reliability rollout status

Recorded on 28 October 2026 (IST).

## Completed

- [Implementation PR #27](https://github.com/AxG-SG/SG/pull/27) is merged; merge commit: `919bdf835991f05cdaabdeac4aecea63add51cbd`.
- Final PR candidate `5245e7ae799c7db530ee823241c31e51fc142271` passed all 24 checks, including the four configured CodeQL languages.
- [Main CI gates ruleset](https://github.com/AxG-SG/SG/rules/25546722) is active and explicitly targets `refs/heads/main`. The actual settings match the reviewed `.github/required-main-ruleset.json` payload.
- PRs and up-to-date branches are required, with zero human approvals and an empty bypass list. Deletion and force pushes are blocked; no merge queue is configured.
- Required checks, all bound to GitHub Actions (15368): **Quality gate**, **Semgrep SAST gate**, **Trivy filesystem gate**, **Trivy images gate**, **Performance gate**.
- Native CodeQL results are required, blocking error-level findings and high/critical security findings.
- [Temporary acceptance PR #29](https://github.com/AxG-SG/SG/pull/29) showed all five missing required gates as Expected, a disabled merge button, and REST `mergeable_state=blocked` while current with main. CodeQL had passed. The PR was closed without merging.
- Documentation-only selection was separately verified in [temporary PR #28](https://github.com/AxG-SG/SG/pull/28), also closed without merging.

## Verification evidence

Final PR [Quality run](https://github.com/AxG-SG/SG/actions/runs/40638024452): 804 frontend unit tests, 737 journey assertions, 140 visual tests, all 110 expected PostgreSQL integration classes without skips, and 644 route/navigation page checks. Both themes were audited at 390, 768, 1280 and 1440 pixels. Axe matched 1,881 baseline entries with zero new entries or severity changes. All 939 original-width entries remain unchanged.

Final strict performance evidence contains 60 successful samples across 20 routes, 10 required resources and 8 freshness entries. The three-iteration job is a regression smoke check.

Post-merge main-push checks passed:

- [Quality](https://github.com/AxG-SG/SG/actions/runs/40643992621)
- [Performance Governance](https://github.com/AxG-SG/SG/actions/runs/40643992753)
- [Trivy filesystem and images](https://github.com/AxG-SG/SG/actions/runs/40643992730)
- [Semgrep](https://github.com/AxG-SG/SG/actions/runs/40643992687)
- CodeQL analyses for Actions, Java/Kotlin, JavaScript/TypeScript and Python.

Main push ran all application verification jobs. Advisory docs-check and the unselected full browser fallback skipped as intended; Quality gate passed.

## Measurements and remaining follow-ups

Main Quality elapsed time was **18.27 minutes**, with **33.15 summed job minutes**, versus the historical 24.5 / 46.2 baseline. These are elapsed and summed job durations, not rounded billed usage. This is a single observation; historical cache state is unknown and it does not complete the three-run controlled PR comparison.

The PR harness-qualification run took 26.08 minutes elapsed / 59.37 summed Quality job minutes, including its additional 24.25-minute four-width browser fallback. Its Ubuntu 24.04 x64 runner used Node 24.21.0 and Temurin 17.0.20+1, with warm Docker, Maven and npm caches. Do not compare that extra workload to ordinary application verification as equivalent coverage.

Still outstanding: three representative application PR measurements with cache/runner labels, and deployed hosting Node 24 alignment (the connected Vercel team exposes no project). Accessibility remediation and live-backend browser release tests remain separate follow-ups.

See [the revised implementation plan](ci-reliability-plan.md) for scope and recovery policy. Enforcement must never be weakened automatically.
