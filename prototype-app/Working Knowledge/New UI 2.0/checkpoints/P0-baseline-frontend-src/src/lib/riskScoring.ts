import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import type { Finding } from '../features/findings/types';

// ─────────────────────────────────────────────────────────────────────────────
// Policy weights — mirrors the 6 triage fields on RiskPolicy
// ─────────────────────────────────────────────────────────────────────────────

export type PolicyWeights = {
  triageExploitabilityWeight: number;
  triageBlastRadiusWeight: number;
  triageEolRiskWeight: number;
  triageSlaBreachWeight: number;
  triageMissingOwnerBoost: number;
  triagePatchGapBoost: number;
};

/** Neutral defaults — exactly reproduce the original hardcoded formula. */
const DEFAULT_POLICY: PolicyWeights = {
  triageExploitabilityWeight: 1.0,
  triageBlastRadiusWeight: 1.0,
  triageEolRiskWeight: 1.0,
  triageSlaBreachWeight: 1.0,
  triageMissingOwnerBoost: 1.0,
  triagePatchGapBoost: 1.0,
};

// ─────────────────────────────────────────────────────────────────────────────
// Shared helpers
// ─────────────────────────────────────────────────────────────────────────────

export type RiskScoreLabel = 'Critical' | 'High' | 'Medium' | 'Low';

export function riskScoreLabel(score: number): RiskScoreLabel {
  if (score >= 9) return 'Critical';
  if (score >= 7) return 'High';
  if (score >= 4) return 'Medium';
  return 'Low';
}

export function riskScoreColor(score: number): string {
  if (score >= 9) return 'var(--critical, #dc3545)';
  if (score >= 7) return 'var(--high, #f57b2a)';
  if (score >= 4) return 'var(--medium, #d9a404)';
  return 'var(--low, #45a669)';
}

// ─────────────────────────────────────────────────────────────────────────────
// CVE Risk Score  (0 – 10)
//
// Built from org-level exposure signals. Score grows as more risk context is
// discovered during investigation and shrinks when CVE is found not applicable.
//
// Max budget breakdown (sums to 10):
//   CVSS base severity  →  0 – 3.0
//   EPSS exploit prob   →  0 – 2.0
//   CISA KEV            →  0 – 1.5
//   Blast radius        →  0 – 1.5
//   EOL component(s)    →  0 – 1.0
//   No patch available  →  0 – 1.0
// ─────────────────────────────────────────────────────────────────────────────

export type CveScoreEvent = {
  stage: string;
  score: number;   // cumulative score after this stage
  delta: number;   // change from previous stage (signed)
  reason: string;
  isNote: boolean; // true = informational only, no score change
};

export type CveRiskScoreResult = {
  score: number;
  label: RiskScoreLabel;
  color: string;
  topReasons: string[];
  journey: CveScoreEvent[];
};

export function computeCveRiskScore(
  item: OrgSpecificCveExposureRecord,
  policy: PolicyWeights = DEFAULT_POLICY,
): CveRiskScoreResult {
  const p = { ...DEFAULT_POLICY, ...policy };
  const journey: CveScoreEvent[] = [];
  const reasons: string[] = [];
  let running = 0;

  function push(stage: string, contrib: number, reason: string): void {
    const next = parseFloat(Math.min(10, Math.max(0, running + contrib)).toFixed(2));
    const delta = parseFloat((next - running).toFixed(2));
    journey.push({ stage, score: next, delta, reason, isNote: false });
    if (delta > 0) reasons.push(reason);
    running = next;
  }

  function note(stage: string, reason: string): void {
    journey.push({ stage, score: parseFloat(running.toFixed(2)), delta: 0, reason, isNote: true });
  }

  // ── Stage 1: CVE Published — base technical severity ─────────────────────
  const cvssC = ((item.cvssScore ?? 0) / 10) * 3.0;
  const epssC = Math.min((item.epssScore ?? 0) * 10, 2.0) * p.triageExploitabilityWeight;
  const cvssStr = item.cvssScore != null ? item.cvssScore.toFixed(1) : 'N/A';
  const epssStr = ((item.epssScore ?? 0) * 100).toFixed(1);
  push(
    'CVE Published',
    cvssC + epssC,
    `CVSS ${cvssStr}${item.epssScore != null ? ` · EPSS ${epssStr}%` : ''}`
  );

  // ── Stage 2: CISA KEV — actively exploited ───────────────────────────────
  if (item.inKev) {
    push('In CISA KEV', 1.5 * p.triageExploitabilityWeight, 'Actively exploited in the wild (CISA KEV)');
  }

  // ── Stage 3: Org exposure — blast radius ─────────────────────────────────
  if (item.matchedAssetCount > 0) {
    const blastC = parseFloat((Math.min(item.matchedAssetCount / 15, 1.5) * p.triageBlastRadiusWeight).toFixed(2));
    push(
      'Org Exposure',
      blastC,
      `${item.matchedAssetCount} asset${item.matchedAssetCount !== 1 ? 's' : ''} impacted across org`
    );
  }

  // ── Stage 4: EOL components — no vendor patches ──────────────────────────
  if (item.eolComponentCount > 0) {
    push(
      'EOL Risk',
      1.0 * p.triageEolRiskWeight,
      `${item.eolComponentCount} EOL component${item.eolComponentCount !== 1 ? 's' : ''} — vendor patches unavailable`
    );
  }

  // ── Stage 5: No patch available ──────────────────────────────────────────
  if (item.noPatchComponentCount > 0) {
    push('No Patch', 1.0 * p.triagePatchGapBoost, 'No vendor fix available — manual mitigations required');
  }

  // ── Stage 6: Applicability decision ──────────────────────────────────────
  if (item.applicability === 'NOT_APPLICABLE') {
    const reduction = -(running * 0.85);
    push(
      'Not Applicable',
      reduction,
      "Confirmed not applicable to this org's inventory — risk reduced"
    );
  } else if (item.applicability === 'APPLICABLE' && item.impactedComponentCount > 0) {
    note(
      'Applicability Confirmed',
      `${item.impactedComponentCount} component${item.impactedComponentCount !== 1 ? 's' : ''} confirmed impacted`
    );
  }

  // ── Stage 7: Findings created ─────────────────────────────────────────────
  if (item.openFindings > 0) {
    note(
      'Findings Created',
      `${item.openFindings} finding${item.openFindings !== 1 ? 's' : ''} raised for remediation tracking`
    );
  }

  const finalScore = parseFloat(Math.min(10, Math.max(0, running)).toFixed(2));
  return {
    score: finalScore,
    label: riskScoreLabel(finalScore),
    color: riskScoreColor(finalScore),
    topReasons: reasons.slice(0, 3),
    journey,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Finding Priority Score  (0 – 10)
//
// Urgency-based score computed from business-impact signals, not just CVSS.
// Answers "how urgently does this specific finding need attention right now?"
//
// Max budget breakdown (sums to 10):
//   Exploitability (KEV / EPSS)  →  0 – 3.0
//   SLA breach proximity          →  0 – 2.5
//   Missing owner                 →  0 – 1.5
//   EOL component                 →  0 – 1.5
//   Severity boost                →  0 – 1.0
//   VEX confirmed affected        →  0 – 0.5
// ─────────────────────────────────────────────────────────────────────────────

export type FindingPriorityScoreResult = {
  score: number;
  label: RiskScoreLabel;
  color: string;
  topReasons: string[];
};

// ─────────────────────────────────────────────────────────────────────────────
// Org Impact  (LOW | MEDIUM | HIGH)
//
// Classifies the organisational impact of a CVE using CVSS, exploitability
// signals (KEV/EPSS), external-facing asset exposure, and the relationship
// between the S.AI risk score and raw CVSS score.
//
// Rules (priority order):
//   HIGH   – CVSS >= 9.0 (critical), OR in CISA KEV, OR EPSS >= 0.3,
//             OR S.AI > CVSS + 1 (context elevates risk),
//             OR any external-facing asset is affected
//   MEDIUM – S.AI is within ±1 of CVSS AND none of the HIGH conditions apply
//   LOW    – S.AI is more than 1 below CVSS AND no HIGH conditions apply
// ─────────────────────────────────────────────────────────────────────────────

export function computeOrgImpact(
  item: OrgSpecificCveExposureRecord,
  saiScore: number,
  externalFacingCount: number,
): 'NONE' | 'LOW' | 'MEDIUM' | 'HIGH' {
  if (item.matchedAssetCount === 0) {
    return 'NONE';
  }

  const cvss = item.cvssScore ?? 0;
  const epss = item.epssScore ?? 0;

  const isCritical = cvss >= 9.0;
  const isExploitable = item.inKev || epss >= 0.3;
  const saiAboveCvss = saiScore > cvss + 1.0;
  const hasExternalFacing = externalFacingCount > 0;

  if (isCritical || isExploitable || saiAboveCvss || hasExternalFacing) {
    return 'HIGH';
  }
  if (Math.abs(saiScore - cvss) <= 1.0) {
    return 'MEDIUM';
  }
  return 'LOW';
}

export function computeFindingPriorityScore(
  finding: Finding,
  policy: PolicyWeights = DEFAULT_POLICY,
): FindingPriorityScoreResult {
  const p = { ...DEFAULT_POLICY, ...policy };
  const reasons: string[] = [];
  let score = 0;
  const now = Date.now();

  // 1. Exploitability (0 – 3.0 × weight)
  if (finding.inKev) {
    score += 3.0 * p.triageExploitabilityWeight;
    reasons.push('In CISA Known Exploited Vulnerabilities');
  } else if ((finding.epss ?? 0) >= 0.5) {
    score += 2.5 * p.triageExploitabilityWeight;
    reasons.push(`Very high EPSS (${(((finding.epss ?? 0) * 100)).toFixed(1)}%)`);
  } else {
    const epssC = Math.min((finding.epss ?? 0) * 15, 2.0) * p.triageExploitabilityWeight;
    score += epssC;
    if (epssC > 0.5) {
      reasons.push(`EPSS ${(((finding.epss ?? 0) * 100)).toFixed(1)}%`);
    }
  }

  // 2. SLA breach proximity (0 – 2.5 × weight)
  if (finding.dueAt) {
    const msToSla = new Date(finding.dueAt).getTime() - now;
    const daysToSla = Math.floor(msToSla / 86_400_000);
    if (daysToSla < 0) {
      score += 2.5 * p.triageSlaBreachWeight;
      reasons.push(`SLA breached ${Math.abs(daysToSla)}d ago`);
    } else if (daysToSla <= 3) {
      score += 2.0 * p.triageSlaBreachWeight;
      reasons.push(`SLA in ${daysToSla}d`);
    } else if (daysToSla <= 7) {
      score += 1.5 * p.triageSlaBreachWeight;
      reasons.push(`SLA in ${daysToSla}d`);
    } else if (daysToSla <= 14) {
      score += 1.0 * p.triageSlaBreachWeight;
    } else if (daysToSla <= 30) {
      score += 0.5 * p.triageSlaBreachWeight;
    }
  } else if (finding.status === 'OPEN') {
    score += 0.3;
    reasons.push('No SLA set');
  }

  // 3. Missing owner (0 – 1.5 × boost)
  const hasOwner = finding.ownership?.displayName || finding.assignedTo;
  if (!hasOwner) {
    score += 1.5 * p.triageMissingOwnerBoost;
    reasons.push('No owner assigned');
  } else if (!finding.assignedTo) {
    score += 0.5 * p.triageMissingOwnerBoost;
  }

  // 4. EOL component (0 – 1.5 × weight)
  if (finding.isEol) {
    score += 1.5 * p.triageEolRiskWeight;
    const days = finding.eolDaysRemaining;
    reasons.push(
      days != null && days < 0
        ? `Component EOL ${Math.abs(days)}d ago`
        : 'EOL component affected'
    );
  }

  // 5. Severity boost (0 – 1.0)
  if (finding.severity === 'CRITICAL') score += 1.0;
  else if (finding.severity === 'HIGH') score += 0.5;

  // 6. VEX confirms affected (0 – 0.5)
  if (finding.vexStatus === 'AFFECTED') {
    score += 0.5;
    reasons.push('VEX confirms affected');
  }

  // Non-open findings are no longer actionable — deprioritise
  if (finding.status !== 'OPEN') {
    score *= 0.1;
  }

  const finalScore = parseFloat(Math.min(10, Math.max(0, score)).toFixed(2));
  return {
    score: finalScore,
    label: riskScoreLabel(finalScore),
    color: riskScoreColor(finalScore),
    topReasons: reasons.slice(0, 3),
  };
}
