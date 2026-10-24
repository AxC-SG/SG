# AI Grid — Known Limitations & Failure Modes

> **LIVING DOCUMENT — keep updating.** These are the boundaries of the current AI Grid approach (agentless
> AWS/Azure config discovery → normalized facts → curated catalog → correlation → AI findings). Revisit every
> time we add a discovery mechanism or capability, and **cite the relevant items in the coverage UI**.
> Last updated: 2026-07-31 (session 6).

**Legend:** 🧱 **Hard limit** of agentless-config (won't work no matter what we build within this mechanism) ·
🕐 **Deferred-capability gap** (works once we build the missing mechanism/capability).

## 1. 🧱 Can't assess what discovery can't see
Control-plane config scan only sees cloud-provisioned AI resources. Blind to: **shadow AI** (code calling
`api.openai.com` directly), **self-hosted AI on compute** (Ollama/vLLM/LangChain in EC2/VM/pod), **most MCP
servers** (found via host filesystem inspection, not control-plane APIs — `cloudPlatform:null` in Wiz's sample),
**SaaS AI** (Copilot/ChatGPT Enterprise/Agentforce), **AI in source not yet deployed**. No artifact → no finding.
*Needs runtime/DNS, host, SaaS-admin, and source discovery mechanisms.*

## 2. 🧱 Config can't prove controls actually work
We read that a guardrail is *attached* + its *strength setting*; we can't tell it *blocks a jailbreak*. Out of
reach of config scanning: **prompt injection** susceptibility (LLM01), **data/model poisoning** (LLM04),
**improper output handling** (LLM05), **misinformation** (LLM09), **model malware/deserialization**, **MCP tool
poisoning**, **guardrail efficacy**. We validate *presence of controls*, not *behavior/content*.

## 3. 🕐 Highest-severity policies return NO_DECISION, not FAIL
Marquee risks live in derived signals we haven't built — `has_admin_privileges` (CIEM), `has_sensitive_data`
(DSPM), validated `is_accessible_from_internet` (ASM). The `UNKNOWN`-aware model correctly returns `NO_DECISION`
(no false positives) — but the product reports **nothing actionable** for the scariest cases until those land,
and **toxic-combination correlation (Epic 5) is empty** until CIEM+DSPM+ASM populate node facts. "Works but
doesn't deliver" early.

## 4. 🕐 Both technology and capabilities can be unknown → inventoried but unassessed
Capabilities are the equalizer for thin-technology artifacts, but capabilities often come from the same derived
signals (#3). Coarse technology + `UNKNOWN` capabilities → matches nothing meaningful; shows in inventory only.

## 5. 🧱/🕐 Single-field config reads are inaccurate without the graph
Both false positives and false negatives: syntactic IAM wildcard ≠ effective permissions (ignores
boundaries/SCPs); `s3Public` via bucket-policy ignores ACLs + account Block-Public-Access; `publicNetworkAccess`
flag ≠ actually reachable (WAF/private DNS/peering). Accurate verdicts need effective-permission + reachability
resolution (CIEM/ASM).

## 6. 🧱 Point-in-time scan misses drift and ephemerality
A 4h cycle: a guardrail disabled right after a scan reads healthy until the next; short-lived agents/endpoints
may never be scanned. Only runtime detection closes this.

## 7. ⚠️ Attribution, dedup, and shared dependencies are ambiguous (design risk)
"One finding per AI artifact" fragments when a **shared dependency** is bad (one public bucket → 5 KBs → 5
findings or 1? whose SLA/owner?), when one logical AI system spans **many artifacts**, or with
**cross-account/cross-provider** composition. Needs deliberate dedup + owning-node rules.

## 8. ⚠️ Ownership & technology-registry are silent-failure surfaces (operational)
Ownership depends on tags→alias→rules; poor tagging → unresolved owner → noise or unrouted findings. The
technology registry is our CPE analog — misclassify a technology (or a vendor rename) and Tier-B policies
**silently don't fire** (false negatives, no error). Registry staleness = invisible coverage loss.

## 9. ⚠️ Coverage can masquerade as safety (product risk — HIGHEST attention)
So much is `NO_DECISION`/`NOT_APPLICABLE`/`UNKNOWN` that a top-line "90% compliant" can be mostly "not
evaluated." **"Green" can mean "we couldn't check," not "secure."** The UI/rollup must foreground the 5-way
status. **Decision: coverage must NEVER present `NO_DECISION` as pass.**

## 10. ⚠️ Scale (engineering)
Wiz's sample tenant: ~14k resources, ~950 agents, ~500 MCP. "Fetch full config for everything + re-correlate
every 4h" won't hold without **incremental/delta discovery** (AWS/SCCM sync already lack delta today).

## Honest scope statement
**Works for:** configuration & posture of *discoverable, cloud-provisioned* AI artifacts and their directly
connected cloud dependencies, expressed as facts, assessed by a curated catalog, routed through the host
workflow. **Does not work for:** undiscoverable artifacts (#1), whether controls actually work (#2), the
highest-severity identity/data/reachability risks + toxic combinations until CIEM/DSPM/ASM (#3), between-scan
drift (#6) — and it can mislead via coverage-as-safety (#9) if the UI doesn't foreground what wasn't evaluated.
