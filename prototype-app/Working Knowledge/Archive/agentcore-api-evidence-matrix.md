# AgentCore API evidence matrix

Decision date: 2026-09-20. Evidence source: AWS control-plane API and developer-guide contracts.

| Relationship | Provider evidence | Stable identifiers | Decision |
|---|---|---|---|
| Runtime → workload identity | `CreateAgentRuntime`/`GetAgentRuntime` return `agentRuntimeArn`, `agentRuntimeId`, and `workloadIdentityDetails.workloadIdentityArn`. | Runtime ARN and workload-identity ARN | Authoritative; emit as identity membership. |
| Runtime → deployment | `ListAgentRuntimeEndpoints` is scoped by runtime ID; endpoints route to explicit runtime versions and `DEFAULT` follows the latest version. | Runtime ID, endpoint name/ARN, runtime version | Authoritative; endpoint/version membership defines the deployable workload boundary. |
| Runtime → version | `ListAgentRuntimeVersions` is scoped by runtime ID. | Runtime ARN/ID and provider version | Authoritative; version is root-ineligible. |
| Runtime → gateway | Runtime code may call a gateway, but the Runtime control-plane response does not declare that dependency. | Independent ARNs only | Not authoritative; retain both resources without synthesizing an edge. |
| Runtime → browser | Runtime code invokes Browser through the SDK; no Runtime control-plane attachment field is documented. | Independent ARNs only | Not authoritative; no inferred edge. |
| Runtime → code interpreter | Runtime code invokes Code Interpreter through the SDK; no Runtime control-plane attachment field is documented. | Independent ARNs only | Not authoritative; no inferred edge. |
| Runtime → memory | Runtime code invokes Memory through the SDK; no Runtime control-plane attachment field is documented. | Independent ARNs only | Not authoritative; no inferred edge. |
| Runtime → tool | Tool use is application/harness configuration, not a Runtime control-plane field. | Depends on tool | Inventory only unless an authoritative harness/runtime response supplies the link. |

## Root-eligibility decision

`AWS_AGENTCORE_RUNTIME` is root-eligible. AWS supplies a stable runtime ARN/provider ID, the Runtime is the provider-defined serverless workload boundary, and runtime-scoped versions/endpoints plus the returned workload identity provide stable provider-backed membership relationships. The collector must never synthesize an `AI_AGENT` for this workload. Browser, interpreter, memory, and gateway resources remain optional standalone inventory until provider-backed attachment evidence is present.

Primary references:

- https://docs.aws.amazon.com/bedrock-agentcore-control/latest/APIReference/API_CreateAgentRuntime.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/agent-runtime-versioning.html
- https://docs.aws.amazon.com/bedrock-agentcore/latest/devguide/harness-vs-runtime.html
