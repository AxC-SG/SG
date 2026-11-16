# CI/CD review fixes

All five findings from the review of `8c17bbf3` are addressed together:

1. Both artifact consumers authenticate the publication-producing run, event, repository, main branch and successful publication job. Quality push publication and manual publication of older qualified candidates remain supported. Release downloads the selected artifact ID and checks its candidate Quality run and gate.
2. A new release persists pending intent before its first mutation. A partial stop, Terraform apply or frontend promotion cannot leave the environment available to unrelated operations.
3. Migration launch intent uses a stable ECS client token; the returned task ARN is saved before waiting. A retry waits on the recorded task instead of starting another.
4. Verification rechecks service revisions, running counts, target health and public/protected HTTP responses after the bake.
5. The security job boots the exact image ID through its normal migrator, API and worker commands against disposable PostgreSQL. Runtime processes use the prod profile, external JWT configuration, production safety validation and the restricted database role. The image is not rebuilt for publication.

The existing Quality gate is the single consolidated acceptance check. Its static job exercises the new failure regressions, and its candidate-image job runs the startup harness before scanning and archiving that image. Cloud deployment and browser acceptance remain separate from this CI check.

Offline regression entry point: `python3 .github/scripts/test-cicd-hardening.py`.
Exact-image entry point: `python3 .github/scripts/check-aws-image-startup.py IMAGE`.
