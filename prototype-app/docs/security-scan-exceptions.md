# Spring MVC advisory applicability — November 12, 2026

PR #70's three Trivy jobs failed after the existing exceptions expired at
00:00 UTC on November 12. They reported CVE-2026-47884 and CVE-2026-47890 in
Spring MVC 6.2.19. Image builds succeeded; this was not the earlier Ubuntu DNS
failure. The previous review is retained in
[the October record](../Working%20Knowledge/Archive/security-scan-exceptions.md).

The exceptions were reassessed against current production Java source and
resources and the current vendor advisories on November 12. They remain limited
to `pkg:maven/org.springframework/spring-webmvc@6.2.19` and these two CVE IDs.
They now expire at **00:00 UTC on November 19, 2026**, requiring another review
before use on or after that date.

- [CVE-2026-47884](https://spring.io/security/cve-2026-47884/) requires an
  `XsltView`, a wildcard mapping that renders a view, and an implicit view name.
  The API's source/resources contain no XSLT views, view resolvers or server-side
  view controllers. Its controllers return REST responses.
- [CVE-2026-47890](https://spring.io/security/cve-2026-47890/) requires SSE view
  fragments and attacker-controlled streamed data. The API's source/resources
  contain no SSE emitters, fragment rendering or event-stream endpoints. React
  renders the frontend separately.

`check-spring-advisory-applicability.py` passes on the current production source
and resources. Its negative controls still reject wildcard imports, reflective
class names, view-controller registration and SSE/fragment-rendering forms.
Both Trivy jobs (filesystem and the AWS backend candidate image) run those
controls and the applicability guard before scanning. A CI contract rejects any job
that omits or runs the guard after its scan. Critical vulnerability enforcement,
scan targets and all other findings remain enabled.

The dependency itself is still affected by version. This record establishes the
absence of the advisory prerequisites in this application; it does not claim a
patched library. Reassess/remove the exceptions if view/SSE features, dynamically
loaded code or external rendering configuration are introduced. Remove them when
adopting an aligned patched Spring release. The vendor lists 6.2.20 as an
enterprise-only fix and 7.0.9 as an OSS fix. A coordinated Boot/Framework major
upgrade needs its own compatibility qualification; replacing only the MVC jar
would mix framework major versions.

The failed run is
[Trivy 43131822238](https://github.com/AxC-SG/SG/actions/runs/43131822238).
Fresh checks on the repaired PR head and, after manual merge, fresh main scans
and exact-SHA backend/frontend artifacts are still required before publication.
