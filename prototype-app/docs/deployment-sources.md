# Deployment sources

Canonical repository: [AxG-SG/SG](https://github.com/AxG-SG/SG).

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
