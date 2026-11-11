Continue ScoutGrid Part 1 in the isolated checkout
`/private/tmp/scoutgrid-part1-postmerge-20261111`, branch
`codex/aws-part1-integrated-lab`. Preserve `/Users/karthik/Desktop/SG`: it is still
on `codex/aws-part-1-implementation` with 217 pre-existing changed entries.
Do not reset, blanket-stash, clean, or commit the primary workspace wholesale.

Read `AWS_MASTER_MIGRATION_PLAN.md`, `STANDARD_IMPLEMENTATION_READINESS.md`, and
`release-evidence/postmerge-20261111/README.md` in this directory. Historical local
lab preparation is also in the primary workspace's
`release-evidence/integrated-lab-20261111/README.md`; it is not current release
approval. Reverify temporary artifacts before reuse.

PR #67 merged as b65b1ee852cfe7b73375db6c075091c3c9c6a351. Its Trivy image builds
failed three attempts on Ubuntu DNS. PR #68 fixed BuildKit DNS and strict bounded
apt retries and was manually merged as
5a95f54fb122ba3b920df130c5c049b43732a8e1. All four required main workflows passed.
The exact scanned archive is retained at
`/private/tmp/scoutgrid-postmerge-artifacts/main-5a95f54/backend/image.tar.gz`;
its SHA-256 is f501f5fd37267d30bb8b7c1e9a08481ddca16a9816510712fea530f99c424ddf.
It packages platform V15 and tenant V20. All 35 SQL files and the exit-once wrapper
match exact main source. Same-SHA frontend reports/journeys are retained locally.

The current branch fixes source-title line height and four reviewed Connect
snapshots, adds retained frontend build evidence, verifies classic/containerd
image identities without dropping integrity checks, and emits unattached lab
publisher/migrator/service policies and a private launch request. Keep all future changes
in one active PR for the owner's manual merge. Never merge or enable auto-merge.
These changes require fresh candidate checks and new main artifacts after merge.
Check the PR for the latest full browser sweep/CI outcome; recorded base-main
checks do not qualify this replacement candidate.

The Sydney application lab has not been deployed. Lab account 736486260824,
ap-southeast-2; lab.scoutgrid.io and api-lab.scoutgrid.io; owner/DNS contact
scoutgrid.io@gmail.com, SG Internal administrator scoutgridtenant@gmail.com.
Keep github_publisher=null and one NAT in the disposable lab. Production account
560246495987/us-east-1 requires zonal NATs and has no change authorization.

Complete reviewed infrastructure apply/teardown policies and effective-role
negative checks, ACM/DNS access, secret metadata/custody, independent exact
candidate approval, ECR publication/digest, exit-once bootstrap with one SG
Internal, and live managed-auth/onboarding/upload/isolation/scheduling tests.
The emitted migrator policy cannot constrain command overrides or network
arguments through IAM: review the exact request under a trusted release operator.
Do not expose secrets or credentials. Do not reuse old keys scheduled for deletion.

The $20 monthly lab ceiling remains; $15 integrated-run reserve is not yet
approved. Billing is estimated and foundation unposted costs/tax are unresolved.
Obtain a concrete bounded run/cleanup authorization before new billable creation.
Do not repeat the completed foundation exercise as a standalone run. The
ten-customer/24-hour Stage B soak, recovery, security/observability, production
cutover and stabilization remain open and require their own evidence and budget.
