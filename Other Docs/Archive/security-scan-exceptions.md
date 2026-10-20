# Spring MVC scan applicability

Reviewed 12 October 2026 for Spring MVC 6.2.19, managed by Spring Boot 3.5.16.
The two entries in `.trivyignore.yaml` expire on 12 November 2026 and apply only
to `pkg:maven/org.springframework/spring-webmvc@6.2.19`. Other vulnerabilities,
packages, and versions retain the existing critical vulnerability gate.

- [CVE-2026-47884](https://spring.io/security/cve-2026-47884/)
  requires `XsltView` and an implicit view name from a wildcard view mapping.
  Production controllers use `@RestController`; production source and resources
  contain no XSLT views, view resolvers, or server-side view controllers.
- [CVE-2026-47890](https://spring.io/security/cve-2026-47890/)
  requires streaming view fragments over SSE with attacker-controlled data.
  Production source and resources contain no SSE emitters, fragment rendering,
  or event-stream endpoints. React renders the frontend separately.

Both Trivy jobs run `check-spring-advisory-applicability.py` before scanning.
The guard conservatively fails on view/SSE API references, including wildcard
imports, reflective class names and resource configuration. Its tests exercise
these alternate forms and an ordinary JSON response. Adding either feature
requires removing or reassessing the exceptions; dynamically supplied code or
configuration must also be reviewed before deployment. This is an applicability
assessment, not a claim that the dependency has been patched.

The vendor lists Framework 6.2.20 as an enterprise-only fix and 7.0.9 as the OSS
fix. The repository has no enterprise artifact repository. A coordinated Boot
major upgrade is separate work; overriding one MVC jar with Framework 7 would
leave incompatible framework modules. Remove the exceptions when adopting an
aligned patched framework or when their prerequisite changes. Reassess by the
expiry date even if the application remains unaffected.
