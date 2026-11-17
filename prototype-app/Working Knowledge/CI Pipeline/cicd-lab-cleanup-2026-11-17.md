# CI/CD and lab cleanup — 2026-11-17

The post-hardening review found duplicated runtime references across four tfvars files, independent publisher/consumer Quality-run validation, leaked release temporary directories, a Terraform copy of the backend host catalogue, repeated verified Terraform installation, workflow tests tied to formatting, and a release script mixing checks and service adapters with orchestration.

One PR addresses all seven. Runtime common JSON and mode overrides render one Terraform var file; the public Terraform input interface is unchanged. Publication consumers and the selector share a validator requiring the canonical workflow ID and path, main push, same repository, optional exact SHA and one successful Quality gate. The CLI cleans its workspace in `finally`. Runtime configuration adds Cognito to application defaults. The Linux installer and local version guards share a manifest. Workflow contracts parse YAML, and offline stubs exercise checksum rejection and private tenant-only smoke configuration. Pure checks, settings, GitHub lookup and the Vercel adapter live in `release_lib/`; test fixtures live in `tests/support.py`.

## Verification

- All eight CI Python suites pass (65 tests); the 87-test release suite and 19 shell cycle checks pass.
- Standard Terraform validation and 40 mocked scenarios pass; the network module validates and its three mocked scenarios pass. Backends were disabled; no live infrastructure was planned or applied.
- Seven operator-script tests, five browser-runner tests and all five Gitleaks checksum controls pass.
- actionlint, ShellCheck for CI/lab scripts, Terraform formatting and diff whitespace checks pass.
- All four rendered modes exactly match the previous HCL tfvars values, including the enrollment reference only in stopped mode.
- The release orchestration class and 32 extracted functions/methods are AST-identical to main.

## Operational impact and rollback

The CLI commands, S3 record format, lock keys, resource addresses and image digest contract remain stable. Historical evidence files remain untouched; current operator docs explain rendering replacement files. Terraform now uses `HTTP_OUTBOUND_ADDITIONAL_ALLOWED_HOSTS`, so release/rollback images must include the support introduced in `bf179fa4`. The first task-environment update uses the reviewed release path; lab cycles continue to refuse task-definition changes. Revert this PR to restore the prior installer, config files, environment variable and module layout. Reverting code does not change live AWS or Vercel resources.

The implementation is isolated from the ownership Release 2 integration. No deployment or live role/policy change is part of this cleanup. Full backend/frontend build and image qualification remain CI gates; local verification here covers the changed tooling and mocked infrastructure.
