# Deployment sources

Canonical repository: [AxC-SG/SG](https://github.com/AxC-SG/SG), repository ID `1427276590`. GitHub confirmed this current owner on 5 November 2026 (Asia/Kolkata). Earlier `AxonCyber-SG/SG` and `AxG-SG/SG` references describe previous locations of the same repository. GitHub now reports a private repository owned by the personal account `AxC-SG`; the local Git origin matches it.

## Current verification — 5 November 2026

| Component | Verified state | Remaining work |
| --- | --- | --- |
| Resend | `scoutgrid.io` verified, sending enabled; only `ScoutGrid_Application_Email_2026_11` remains; no webhooks | No repository setting to change; preserve the working key and verified sender |
| Render backend | `scout-backend` now references `AxC-SG/SG`, branch `main`, auto deploy disabled | Three latest attempts of commit `98155ae6d11e909fe87402a809c0f0804c5c8cd6` are `update_failed`; inspect diagnostics before another rollout |
| Render migrator | `scout-tenant-migrator-demotest1` still references `ggkarthik/Scout` | Review its role, command, and database target before repointing or deploying it |
| Render Postgres | `scoutdb-preprod-v1` is `available`, PostgreSQL 18, Oregon | No Git source connection; replacement or migration is a separate release operation |
| Vercel frontend | Project query filtered by repository ID `1427276590` returns `scout-frontend`; production uses SG's `main` | The separate latest preview is blocked with a team-configuration troubleshooting link |

Production domain `scoutgrid.io` points to Vercel deployment `dpl_9QvQ8GErSssZmv2tvdjULp28RTdf`, which is `READY`. Its Git metadata identifies `AxC-SG/SG`, `main`, commit `98155ae6d11e909fe87402a809c0f0804c5c8cd6`, and source `git`. The Git connection and a production frontend deployment from SG are established.

The latest preview `dpl_5FJghgbSRbwM3VLVFfbLj2JpvKeX`, branch `docs/ui2-browser-ci`, commit `f9426447e18c6f3c4c836e3f1c14e0943fb93a22`, is `BLOCKED`. It is not the deployment serving production. Inspect commit attribution and the Git login connection; the error link alone does not establish the exact cause. The former private-organization/Hobby diagnosis must not be applied automatically to the repository's current personal owner. Do not make the repository public, change subscriptions, rewrite authorship, or weaken deployment protection to bypass this failure. See [Vercel collaboration troubleshooting](https://vercel.com/docs/deployments/troubleshoot-project-collaboration#team-configuration).

Render's latest failed attempt is `dep-dblv93g8v5cc73d2ail0`, finished on 5 November 2026 at 03:15:48 UTC. Updated source configuration does not establish a successful release or current workload health. No backend failure cause or schema compatibility is claimed by this check.

`render.yaml` now declares `AxC-SG/SG`. Preserve the live service's root `prototype-app/backend`, Docker context `.`, Dockerfile `./Dockerfile`, and readiness path `/actuator/health/readiness`. The Blueprint remains a preproduction definition with repository-root Docker paths. Do not perform a full Blueprint sync solely to update the repository URL: its compute plan and environment profile differ from the live service.

This recheck changes only the local repository URL and documentation. It does not publish changes, deploy code, modify external settings or database state, rotate credentials, or send email.

## Historical checkpoint — 1 November 2026

The sections below retain the earlier migration evidence and instructions as recorded on 1 November. Pending Git-linking work and public-visibility statements below are superseded by the current verification above.

Configuration changes are maintained on `codex/resend-email-setup`. Production continues to use `main`; the feature branch is the preview and review source until merged.

## Vercel frontend

The existing project is `scout-frontend` in the Scout team (`scoutgrid`), project ID `prj_BTTCC6KBOQSkBaihL6MZd07ezJn2`. Keep this project so its environment variables, domains, and deployment protection remain attached.

| Setting | Value |
| --- | --- |
| Git repository | `AxG-SG/SG` |
| Production branch | `main` |
| Root directory | `prototype-app/frontend` |
| Framework | Vite |
| Node.js | `24.x` |
| Install command | `npm ci` |
| Build command | `npm run build` |
| Output directory | `dist` |
| Configuration file | `prototype-app/frontend/vercel.json` |

On 1 November 2026, the existing project's root directory, framework, Node version, and install/build/output settings were updated through Vercel MCP. The earlier production deployment identified `ggkarthik/Scout` and was `BLOCKED`.

The repository owner made `AxG-SG/SG` public during this migration. GitHub MCP confirmed that visibility change. A Vercel preview deployment was then accepted from repository ID `1427276590`, branch `codex/resend-email-setup`, commit `b10d751506fc26777531a4452940399b8d9352f6`. Its metadata explicitly identifies `githubOrg=AxG-SG` and `githubRepo=SG`, confirming that Vercel can fetch the new source. The earlier private-organization/Hobby plan restriction no longer applies to this public source.

Automatic Git linking is still a separate pending action. Vercel's project query filtered by the new repository ID returns no linked project. The connected GitHub integration still exposes only the restricted `ggkarthik` namespace. An organization owner/member must grant the Vercel GitHub App access to `AxG-SG/SG` and connect the existing project to that repository. A successful explicit preview deployment does not prove automatic deployment on future pushes.

Open [the existing project's Git settings](https://vercel.com/scoutgrid/scout-frontend/settings/git), change the Connected Git Repository to `AxG-SG/SG`, and keep `main` as the production branch. Use the existing project rather than importing a duplicate. Keep the repository public while using the current Hobby plan for Git deployment; if it is made private again, an eligible Pro/Enterprise team and contributor access are required. No subscription was changed by the agent. The available Vercel MCP tools can configure projects and deploy from a supplied Git source but do not expose reconnecting this existing project's Git repository.

References: [Vercel GitHub repository connections](https://vercel.com/docs/git/vercel-for-github#changing-the-github-repository-of-a-project), [private repository requirements](https://vercel.com/docs/git#deploying-private-git-repositories).

## Render backend and Resend

The existing `scout-backend` service is `srv-d9b802laeets73ahf5dg` in the confirmed Scout Render workspace. It sends transactional email through Resend. Resend does not have a Git repository setting: its domain and sending key remain the working final setup documented in [Resend email configuration](resend-email-setup.md).

`render.yaml` explicitly declares `https://github.com/AxG-SG/SG` and `main`. Its Docker context and Dockerfile paths remain relative to the repository root.

The live Render service still reports `https://github.com/ggkarthik/Scout`. The available Render MCP tools can inspect this service and update environment variables, but cannot change its repository. In [the existing backend settings](https://dashboard.render.com/web/srv-d9b802laeets73ahf5dg/settings), change only the Git repository to `https://github.com/AxG-SG/SG` and retain:

- Branch: `main`.
- Current service root: `prototype-app/backend`.
- Docker context: `.` and Dockerfile: `./Dockerfile` for that root.
- Auto deploy: disabled, matching the current live service.
- Existing environment variables, including the Resend key, sender, domain, encryption key, and application URL.

The live service and Blueprint currently use different root-directory conventions: the Blueprint's Docker paths include `prototype-app/backend`, while the live service sets that directory as its root. Both conventions point to the same Docker build. Do not combine the live root with the Blueprint's prefixed Docker paths. This repository update is not a full Blueprint sync; a full sync would also apply unrelated declared settings, including a different compute plan.

The source repository is now public; if using an authenticated Git connection, grant Render the required repository access. No backend redeployment or migration was triggered as part of this repository-source configuration change.

## Verification status

- The GitHub branch exists in `AxG-SG/SG` and contains the tested Resend configuration.
- Vercel accepted the frontend build-settings update through MCP.
- An explicit Vercel preview was accepted from `AxG-SG/SG` and the existing feature branch. Permanent automatic Vercel Git linking and the live Render Git source change remain pending the dashboard actions above.
- The configuration commit `8761ba846deb6ecbde2c0dd93f956e20aaac0e57` was pushed on the same branch and deployed successfully to [the Vercel preview](https://scout-frontend-l27wzgbwt-scoutgrid.vercel.app). Deployment `dpl_5KVMBYdk4cSLapyCrxnC5Cpqp2VW` reached `READY`; its Git metadata confirms `AxG-SG/SG`, `codex/resend-email-setup`, and that exact commit. This is a preview, not a production promotion.
- Protected-route smoke testing remains unverified: Vercel's authenticated fetch returned HTTP 403 while reading deployment protection access, including after the user completed the requested Scout team consent. Team-scoped project reads also returned 404, while direct project/deployment reads and explicit Git-source deployment succeeded. Deployment protection was preserved.
- `npm ci` and the complete production build, including TypeScript, Vite, and production bundle checks, passed in a Node 24 container.
- `render.yaml` passes the current official Render JSON Schema. The frontend configuration passes the official Vercel schema constraints; Vercel's published schema mixes draft declarations, so schema meta-validation was disabled for that check.
- The working Resend key and verified sender were preserved. Prior successful tenant activation and member invitation delivery evidence remains in the Resend configuration report.
