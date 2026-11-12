# Part 1 post-merge qualification — November 11, 2026

Part 1 remains open. This record separates verified main release bytes from the
replacement frontend/release-tooling candidate and the undeployed Sydney lab.

## Latest continuation — November 12

The owner manually merged PR #69 at `4678580ab0a84c6cd2dfd96a02cfedc168e0a9cf`.
All four main-push workflows passed: Quality 43067107769, Trivy 43067107850,
Semgrep 43067107669 and Performance 43067107897. Browser sweep 43061543315 passed
on PR head `5dfb9ed3`; its tree exactly matches the merged commit. Exact new-main
backend and frontend artifacts are retained in
`/private/tmp/scoutgrid-postmerge-artifacts/main-4678580/`; offline verification
is recorded there. These remain unpublished and the frontend uses CI defaults.
The older `5a95f54` evidence below remains historical.

The owner authorized one replacement PR for the $50 budget records and guard,
on branch `codex/aws-part1-budget-50`. It is the sole active change PR. After its
manual merge, qualify the exact new main SHA and retain its new backend/frontend
pair. Do not treat prior artifacts as qualification for changed source. Read the
[current authorization](EXECUTION_AUTHORIZATION_20261111.md) and handoff for the
$25 inclusive application reserve and outstanding release/access/secret work.

## Verified main release

PR #68 was manually merged as `5a95f54fb122ba3b920df130c5c049b43732a8e1`.
All four main-push workflows passed: [Quality 43050167812](https://github.com/AxC-SG/SG/actions/runs/43050167812),
[Trivy 43050166880](https://github.com/AxC-SG/SG/actions/runs/43050166880),
[Semgrep 43050166823](https://github.com/AxC-SG/SG/actions/runs/43050166823), and
[Performance Governance 43050167767](https://github.com/AxC-SG/SG/actions/runs/43050167767).
The earlier `b65b1ee` Trivy run failed three attempts on Ubuntu DNS; those failed
builds produced no backend release archive. The explicit BuildKit DNS repair
retains vulnerability enforcement and authenticated package indexes.

Artifact `13868309205`, `aws-backend-candidate-43050166880`, is retained locally at
`/private/tmp/scoutgrid-postmerge-artifacts/main-5a95f54/backend/` and on GitHub
until November 25 at 15:41:10 UTC. Its compressed image archive SHA-256 is
`f501f5fd37267d30bb8b7c1e9a08481ddca16a9816510712fea530f99c424ddf`.
The configuration digest is
`sha256:86fe59b7be631d9aa7b4a2e2869c76223439acf8693f770ded6c00b912c63579`.
The saved OCI manifest digest is
`sha256:a77702d3d175e721b228ec11b89520abf606a371abb90257c908187e0d046410`.
Neither establishes an ECR publication digest.

Docker 29's local containerd store reports the saved OCI manifest as `.Id`;
the CI release manifest records the configuration digest. Both were verified
against the archived JSON bytes. The new archive verifier accepts only those
two content-addressed identities and also compares loaded filesystem layers,
platform and runtime configuration. It rejects changed archives, wrong source
SHAs, unrelated images, changed runtime settings and substituted OCI configs.
The publication workflow uses the verifier before and after loading, but remains
disabled for this lab: `github_publisher = null`.

Offline inspection verified non-root Linux/amd64, both pinned regional RDS CA
bundles, platform V15/tenant V20, and all 35 packaged SQL files plus the exit-once
wrapper byte-for-byte against this exact main source. See the JSON records here.

Same-SHA frontend coverage and fixture journey artifacts from Quality were
retained alongside the archive. The existing main workflow does not retain the
built frontend bundle; this candidate adds a checksummed bundle, per-file hashes
and source/run manifest for successful main builds. That CI-default build is not
a configured live Sydney frontend: its eventual API/auth/Turnstile configuration
must have its own recorded build and approval.

## Replacement browser candidate

[Sweep 43036289397](https://github.com/AxC-SG/SG/actions/runs/43036289397) passed the
route/accessibility stages but failed two mobile Connect screenshots. Repeated
captures reproduced raster differences despite identical switch geometry.
An explicit 18px source-title line height replaces the inherited fractional
height. Four affected Connect baselines were reviewed in before/after sheets;
all source labels, enabled states and controls remain present. The unchanged
0.001 screenshot tolerance passed all 40 repeated Connect comparisons and all
172 full visual comparisons. Accessibility and journey baselines are unchanged.
The four-width local route/accessibility sweep also passed: 780 route checks
and no new accessibility regressions. Exact-branch remote qualification remains
recorded in the PR validation results. This is automated visual review, not owner design
approval or live AWS browser qualification.

Branch `codex/aws-part1-integrated-lab` is based on the verified main SHA above.
Its frontend and release-tooling changes select a replacement candidate. It
requires fresh required checks and, after manual merge, fresh same-SHA main
artifacts. Do not promote the retained `5a95f54` archive as evidence for changed
source, and do not reuse `cd741250` artifacts.

## Access and live entry conditions

The Standard root now emits unattached image-publisher, migration-operator and service-operator
policy documents, bound to the actual plan's repository, exact task revision,
execution role and cluster, plus a private exit-once launch request. No role or
policy is attached by these outputs. The offline suite passed all 18 Standard
plans; the two affected plans passed again after correcting condition operators.
AWS Access Analyzer returned zero findings for all three generated documents, and
38 positive/negative IAM simulations passed with distinct task and role identities. The simulation ARNs are explicitly
synthetic; repeat on final live ARNs and effective assumed roles before use.

The migration operator can pass only the migrator execution role and cannot
register task definitions. Launch tags are limited to RunTask creation, and
inspection/stopping is limited to tagged migration tasks. ECS IAM does not
constrain command/environment overrides or RunTask subnet/security-group/public-IP
parameters. Treat this as a privileged, trusted, short-lived release session;
review the exact launch request. These documents do not constitute a complete
infrastructure apply/teardown role or authorize arbitrary IAM policy writes.
The service operator can select only the exact API/worker revisions and private
subnets; it cannot select or pass the migrator, register task definitions, or run
one-shot tasks. IAM does not cap service desired counts, so reviewed plans and
the bounded run procedure still govern spend.

A fresh metadata-only AWS inventory confirmed account `736486260824`, Sydney,
with no ACM certificates, secrets, ECR repositories, ECS clusters, RDS instances,
ALBs, Amplify apps or Cognito pools. No hosted zones were returned. No resources
were created, no credentials/secret values were retrieved, and no production
change occurred. The primary workspace remains on its original branch with
217 changed entries; all edits are in the isolated temporary checkout.

The November 12 billing refresh estimates $0.2371053074, excluding credits/refunds.
Some foundation usage has posted; final usage and tax remain unreconciled. The
updated bound deliberately adds posted costs to the retained allowance, without
netting out overlap, to avoid undercounting. The owner has
superseded the historical $20 ceiling with **$50 total for the month**, inclusive
of prior/unposted charges, tax and contingency, and authorized the bounded
application lab. Allocate **$25 inclusive** to the application run; the conservative
prior-run bound is $4.59 and modeled eight-hour application cost is $16.69 inclusive.
The remaining $20.41 is unallocated contingency, not authorization for more scope.
Target four hours; complete cleanup by eight. See the [current authorization](EXECUTION_AUTHORIZATION_20261111.md)
and [reproducible budget](authorized-budget-20261111.json). Do not re-request this
budget approval. The old `billing-readback.json`, `lab-inventory.json` and
`dns-readiness.json` are historical observations; the current readback confirms
an issued, unused, non-exportable API ACM certificate and its saved DNS-only CNAME.
No application routing record or billable application stack exists. Complete
infrastructure/operator scopes, live plans, secret custody and independent exact
candidate approval before billable creation. The previous 56-resource foundation
exercise must not be repeated on its own.

Part 1 still requires live managed sign-in, onboarding and email receipt, durable
imports, isolation and scheduling/replacement qualification, security/observability,
Stage B ten-customer/24-hour capacity, timed recovery, production approval/cutover
and stabilization. The disposable lab budget does not authorize Stage B or
production. Preserve the previous keys' December 11 deletion schedules.

The pinned Gitleaks scan initially matched two verified SQL checksum records.
The exception is limited to the exact manifest, two SQL record names, hash shape
and generic-api-key rule. A full candidate-ancestry scan also reviewed twelve
historical documentation matches: two ordinary prose lines and ten localhost
curl examples. Their exceptions are exact commit/file/rule/line fingerprints.
Five positive/negative controls preserve detection of credential-shaped values,
wrong paths and new curl headers in the same historical filename. The complete
candidate ancestry passed after source review; no scanner scope was reduced.

Cloudflare DNS access is available in the signed-in owner session. The eleven
observed records contain no lab hostnames; production still points to Vercel and
Render. That was the earlier inventory. The exact API ACM validation CNAME was subsequently
owner-approved and saved; no application-routing DNS record has been created.
