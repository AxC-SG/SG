# Migration reset — 2026-09-04

The pre-customer migration history was consolidated into independent platform and tenant V1 baselines. The reset covers only local, demo, and staging databases containing test data.

Before deploying this revision, export each non-production database, stop workers, and drop the schemas and Flyway history tables together. Run the privileged schema bootstrap, verify tenant checksums/RLS/control-plane status, then reseed approved demo data and restart workers. Never delete Flyway history separately from its schema.

Routine migrations are append-only. Existing migration files must not be edited, renamed, or deleted. CI compares each pull request with its base branch and the required merge-queue run checks the combined catalog for duplicate versions.

The October 2026 catalog repair retires two accidentally committed platform V4 files and one tenant V4 file
that collided with the existing AI Grid V4. The GHSA schemas remain in platform V6 and tenant V12; the OSV
schema is introduced at V7. CI permits deletion of only those three named files.
Before applying this repair to a database with migration history, inspect its
Flyway history: any environment that applied either retired V4 requires a planned
schema and history reconciliation rather than an automatic rollout.
