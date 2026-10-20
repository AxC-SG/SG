# runtime-topology-check

Verified read-only on 2026-10-20 in the user-confirmed Render **Scout** workspace (`tea-d9adqh3eo5us739qcfag`). Source: Render service list/details and latest deploy metadata. No deployment or configuration change was performed.

| Actual service | Type / instance count | Revision / latest observed deployment | Effective application role and scheduler flags |
|---|---|---|---|
| `scout-backend` (`srv-d9b802laeets73ahf5dg`) | Docker web service, 1 instance; readiness path `/actuator/health/readiness` | `acb4bfc0a0259ce98c01cc820bbbc50e76ff8b1f`, latest deployment marked `live`, finished 2026-10-06T06:58:12Z; auto-deploy off | Not exposed by available read-only service metadata; pending authoritative runtime/env evidence |
| `scout-tenant-migrator-demotest1` (`srv-dafbtvdg1s2s73dthf0g`) | Docker web service, 1 instance, not suspended | `d87e5cd51a556ad926ff90e10686dcad29d7e574`, latest deployment marked `live`, finished 2026-09-15T16:23:05Z | Role, command, completion state and remaining credential access unverified; service remains present |

No dedicated worker service was returned in this workspace's non-preview service listing. This does not prove schedulers are disabled, that no preview/other workspace exists, or that a web service has only API responsibilities. The local `render.yaml` is intended configuration, not evidence of these running processes' environment.

Compare these facts with [PHASE_3_SCHEDULE_MATRIX.md](PHASE_3_SCHEDULE_MATRIX.md). P13 release qualification remains pending until effective `APP_RUNTIME_ROLE`, `APP_SCHEDULING_ENABLED`, per-path flags, cron time zone and running revision are verified. A single currently listed backend replica is not a substitute for safe database coordination. Restricted-role TLS/hostname verification against the current environment is also pending; no credentials or connection strings were retrieved.

The October 20 local continuation pins every source cron annotation to UTC and introduces platform V5 schedule coordination. This does not change the older deployed revisions listed above or verify their effective clocks, roles or scheduler flags.
