# BOM ingest API (CI/CD)

Push SBOM, AI BOM, CBOM or Vendor BOM documents from a pipeline. The document is the request body; the
`Content-Type` names its serialization. Ingestion reuses the upload path (`BomIngestionOrchestrator`), so
parsing, source tracking and correlation behave exactly as for a manual upload.

## Authentication

Create an **ingest key** in *Connect → BOM Management → CI/CD pipeline API* (tenant administrators only).
The key is shown once; store it as a pipeline secret and send it as `Authorization: Bearer sgk_...`.

A key can call only the two endpoints below. Anywhere else it gets `403 KEY_SCOPE`. It cannot assert
`completeness=COMPLETE_ASSET_SOFTWARE` (an inventory administrator's claim) and cannot manage keys. Keys can
expire and be revoked; a revoked, expired, wrong or malformed key returns `401 INVALID_KEY`. Only a SHA-256 of
the secret is stored (`platform.bom_ingest_api_keys`).

## Push a document

`POST /api/bom/ingest?bomType=SBOM`

| Parameter | Required | Meaning |
|---|---|---|
| `bomType` | yes | `SBOM`, `AI_BOM`, `CBOM`, `VENDOR` |
| `assetName`, `assetIdentifier`, `assetType`, `supplier` | no | Derived from the document when omitted. The derived identifier drops the component version so each release updates the same asset. Pass `assetIdentifier` to choose the grouping. `assetType`: `APPLICATION`, `HOST`, `CONTAINER_IMAGE` |
| `correlator` | no | Identity of this pipeline's source (for example the repository or one matrix job). Without it the source is the asset identifier |
| `pipeline`, `buildId` | no | Recorded on the stored document and shown in the *Recent pipeline pushes* table (80 / 200 characters) |
| `completeness` | no | `PARTIAL` (default) or `COMPLETE_ASSET_SOFTWARE` (not allowed with a key) |

Formats: CycloneDX JSON and XML, SPDX JSON and SPDX XML (`application/json`, `application/xml`, `text/xml`,
or a `+json` / `+xml` type). Up to 50 MB.

```bash
curl --fail-with-body -sS -X POST \
  "https://<host>/api/bom/ingest?bomType=SBOM&pipeline=github-actions&buildId=$GITHUB_RUN_ID&correlator=$GITHUB_REPOSITORY" \
  -H "Authorization: Bearer $SCOUTGRID_INGEST_KEY" \
  -H "Content-Type: application/json" \
  --data-binary @bom.json
```

Use `--data-binary`, not `-d`, which strips newlines from the document.

### Result

`201` (`action: CREATED`) for a new source, `200` otherwise. `action` is:

- `CREATED` - first document for this source.
- `REPLACED` - a new version superseded the source's current one.
- `UNCHANGED` - the same bytes were already the current version. This makes a retried pipeline step safe.

The body carries `bomId`, `assetId`, `sourceId`, `format`, `formatVersion`, `documentFormat`, `componentCount`,
`findingsGenerated`, `warnings` and `statusUrl`.

## Status

`GET /api/bom/ingest/{bomId}/status` returns `state` (`ACTIVE`, `SUPERSEDED`, `FAILED`), `componentCount`,
`pipeline`, `build`, `correlator`, `ingestedAt` and `supersededBy`.

## CBOM CI gate

A CBOM push (`bomType=CBOM`) accepts an optional `environment` (1–40 lowercase letters, digits or hyphens;
default `default`) and returns a single-job `gateToken` (`sgg_…`) and `gateEnvironment`. The token is shown
once, stored only as a SHA-256, expires after 24 hours and reads the gate result of that one document only.

Poll the document's status with both the ingest key and the token:

```bash
curl -H "Authorization: Bearer $SCOUT_INGEST_KEY" -H "X-Scout-Gate-Token: $GATE_TOKEN" \
  https://api.scoutgrid.io/api/bom/ingest/$BOM_ID/status
```

The response then carries `gate`: `state` is `PENDING` (assessment not finished; retry after
`pollAfterSeconds`), `PASS`, `FAIL` (with `reasons`) or `INDETERMINATE` (invalid document or failed
assessment), plus the `assessmentRunId`, `rulePackageDigest` and `artifactChecksum` the decision used.
Without the token the status response has no `gate`; a token for another document, an unknown token and
an expired token all return 403. The ingest key alone never reads findings, reports or gate results.

Gate policies are per environment (`GET/PUT /api/bom/cbom/governance/gate-policies/{environment}`, write
requires `TENANT_ADMIN`): `failOnSeverities`, `minimumCompleteness` and `blockOnInvalid`. An environment
without a policy uses the `default` policy, then the application default (fail on `CRITICAL`/`HIGH`,
completeness at least 0.80, invalid documents block).

## Errors

Every error carries a stable `code`.

| Status | Code | Cause |
|---|---|---|
| 400 | `MISSING_CONTENT_TYPE`, `UNSUPPORTED_CONTENT_TYPE` | `Content-Type` absent, or not JSON/XML |
| 400 | `EMPTY_BODY`, `INVALID_PARAMETER` | empty body; bad or missing query parameter |
| 401 | `INVALID_KEY` | key invalid, expired, revoked or ingest keys unavailable |
| 403 | `KEY_SCOPE`, `COMPLETENESS_NOT_PERMITTED` | key used outside the ingest endpoints; completeness claim |
| 404 | `BOM_NOT_FOUND` | unknown `bomId` |
| 409 | `DUPLICATE_SERIAL_NUMBER`, `INGEST_IN_PROGRESS` | different content reusing a serial number or SPDX namespace; another ingest for the asset is running |
| 413 | `BOM_TOO_LARGE` | over 50 MB |
| 422 | `INVALID_DOCUMENT`, `UNSUPPORTED_FORMAT`, `ASSET_NOT_DERIVABLE`, `NO_COMPONENTS`, `INGESTION_FAILED` | unparseable; not CycloneDX/SPDX; asset not named in the document and not passed; nothing extractable |

Generate a new CycloneDX `serialNumber` (or SPDX `documentNamespace`) for each build. A document that reuses
one with different content is rejected rather than silently dropped.

## Key management

Tenant administrators: `GET/POST /api/bom/ingest-keys`, `DELETE /api/bom/ingest-keys/{id}` (revoke).
Inventory administrators may list. Create and revoke are audited (`bom_ingest_key.created`,
`bom_ingest_key.revoked`) as is every push (`bom.api_ingest`).
