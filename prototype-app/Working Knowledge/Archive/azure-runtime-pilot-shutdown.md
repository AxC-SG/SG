# Azure runtime pilot shutdown

Owner: the platform operator responsible for the existing Azure subscription. This runbook is separate from the application code rollout. Prepare a live-state change record and obtain explicit approval before executing cloud mutations. No Azure changes are executed by the runtime exclusion code PR.

## Identify and verify

The September pilot used subscription `85de82e7-db21-4879-ace4-e5e4093ac0f0`, tenant `6ca05ef5-404c-4feb-a26c-b00a77dfb9d0`, resource group `ai-discovery-rg`, Container App `scout-runtime-pilot-gateway`, and DCR `scout-runtime-evidence-dcr`. Its managed identity principal was `654bb1b8-0c89-4893-9039-1536d5a9d37d`; the scoped Monitoring Metrics Publisher assignment was `96f3c792-3e90-485b-a82f-d2d73b7c8ef4`. These are historical identifiers, not proof of current state.

Read the live resources through Azure MCP. Verify ownership/tags, all active revisions, ingress settings, identity, the role assignment's principal/role/scope, and any bridge or schedule sending data to NoScan. Record the resource IDs and current settings for the approval/change record. If a resource is already absent or inactive, record it and skip that step. Stop on any identity/scope mismatch.

## Approved shutdown

1. Stop pilot bridge/scheduler producers.
2. Disable gateway ingress and deactivate every active Container App revision. Setting minReplicas to zero alone is insufficient because incoming requests can activate it.
3. Remove only the verified pilot identity's Monitoring Metrics Publisher assignment scoped to the pilot DCR. Do not alter shared monitoring identities or subscription roles.
4. Verify no active revisions, no externally callable run endpoint, no producer schedule, and no new pilot events after the shutdown timestamp.

Development pilot data is disposable. After the live-state checks and shutdown approval, delete the dedicated pilot Container App, DCR, and `ScoutRuntimeEvidence_CL` table, including its old evidence. Verify those resources are used only by this pilot before deleting them. Keep the shared `ravikanukollu-1991-resource-logs` workspace and Container Apps environment; they may serve unrelated resources. No evidence export or archival step is required.
