# Trivy scan exceptions

There are no active Trivy exceptions. `.trivyignore.yaml` is empty, and both
Trivy jobs (filesystem and the AWS backend candidate image) enforce every
CRITICAL finding.

## Spring MVC CVE-2026-47884 and CVE-2026-47890 — resolved November 14, 2026

These two advisories affected `spring-webmvc` 6.2.19, which Spring Boot 3.5.16
brought in. The vendor fixed them in Spring Framework 6.2.20 (enterprise-only)
and 7.0.9 (open source).

- [CVE-2026-47884](https://spring.io/security/cve-2026-47884/) required an
  `XsltView`, a wildcard mapping that renders a view, and an implicit view name.
- [CVE-2026-47890](https://spring.io/security/cve-2026-47890/) required SSE view
  fragments and attacker-controlled streamed data.

From November 12 to November 14 they were time-limited exceptions. The basis
was that the API has no server-side view rendering or SSE endpoints, and
`check-spring-advisory-applicability.py` checked that before every scan. The
exceptions were due to expire at 00:00 UTC on November 19.

The Spring Boot 4.1.2 upgrade brings Spring Framework 7.0.10, which contains the
fix. The exceptions, the applicability guard and its CI contract were removed
in the same change. The earlier review is in
[the October record](../Working%20Knowledge/Archive/security-scan-exceptions.md),
and the November 12 failure in
[Trivy 43131822238](https://github.com/AxC-SG/SG/actions/runs/43131822238).

## Adding an exception

An exception needs all of the following:
- an exact package URL and CVE ID;
- an `expired_at` date;
- a statement explaining why the vulnerable code path cannot be reached;
- an entry in this record.

Prefer upgrading the dependency. Never lower the CRITICAL threshold or add broad
suppressions to get a green result.
