# Runtime telemetry deferred from the current release

Agent execution events, logs, execution timelines, runtime graph overlays, telemetry readiness, and runtime findings are outside the current release. Static definition/configuration discovery and posture assessment remain supported, including AgentCore runtime deployment configuration and cloud diagnostic-settings configuration. Azure ML jobs/pipeline runs and their run-derived relationships are excluded; deployed ML endpoints, models, compute, and workspaces remain supported.

`app.ai-security.runtime.enabled` defaults to false. Setting it true fails startup in every environment. Independent release guards reject adapter admission and manual collector calls with HTTP 410 / `RUNTIME_OUT_OF_SCOPE`; the worker never claims batches and the evaluator never reads execution records. Static scans do not invoke the runtime evaluator. Copilot permission tests do not query transcripts. Curated `SCOUT_AWS_ACTIVITY` and `activity.*` evidence are also rejected; historical activity facts do not affect exposure priority.

Runtime APIs for executions/timelines, ingestion/receipts, manual runtime runs, and telemetry readiness are retired with HTTP 410. Runtime graph requests are rejected, while definition graph requests continue. Legacy `/inventory/ai/executions` bookmarks redirect to `/inventory/ai`. Customer findings lists, counts, and details exclude `AI_RUNTIME`; direct customer detail requests return 404. Runtime policies cannot be activated individually or through bulk enable and do not contribute to customer policy totals/framework coverage.

The development histories are consolidated into platform V1 and tenant V1. Platform V1 seeds no AGCF-RT distributions. Catalog distributions with runtime evaluation modes are `available=false`, `default_selection=DISABLED`, `rollout_stage=PAUSED`, and no pinned version. Tenant V1 starts with empty runtime execution, event, participant, producer, source, receipt, quota, job, and finding tables. Static schema, catalog definitions, deployment metadata, and harm baselines remain supported. The runtime-retention scheduler is disabled. Old development data does not need to be retained.

## Rollout

1. Pause external producers and stop old application/worker instances before applying the migrations; a mixed deployment could let old workers continue writing.
2. Remove explicit `APP_AI_SECURITY_RUNTIME_ENABLED=true` settings. Recreate the development database, clear old packaged migrations with `mvn clean`, and bootstrap platform V1 and each tenant V1 through the normal tools. Do not repair old Flyway history or overlay V1 on a populated schema; then start the updated application.
3. Verify static discovery and posture, rejected runtime endpoints, no new execution/event rows, no runtime findings or controls, and empty runtime-data tables after the fresh bootstrap.
4. Keep runtime disabled during rollback. Do not restore old tenant overrides or distributions as part of an application rollback.

Azure pilot shutdown is a separate operational change described in [azure-runtime-pilot-shutdown.md](azure-runtime-pilot-shutdown.md).

Legacy posture policies with a null `evaluation_mode` remain visible and configurable through the compatibility API. Runtime exclusion filters treat that legacy null as a non-runtime mode while still excluding explicit `RUNTIME_*` modes and `AGCF-RT-*` policy IDs. The readiness integration test verifies the baseline has zero active sources and uses explicit disposable fixtures to exercise populated dashboard queries.

The dormant execution finding creation branches and runtime evaluator reconciliation hook have been removed. Restoring runtime findings requires rebuilding that hook, restoring explicit subject handling, and reviewing the reconciliation rejection, activation/startup guards, historical `AI_RUNTIME` exclusions, and retired responses together. Enabling a catalog distribution alone cannot restore runtime findings. AgentCore static deployment discovery remains supported.
