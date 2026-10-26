import { describe, it, expect } from 'vitest';
import {
  computeCveRiskScore,
  computeFindingPriorityScore,
  computeOrgImpact,
  riskScoreLabel,
  riskScoreColor,
  type PolicyWeights,
} from './riskScoring';
import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import type { Finding } from '../features/findings/types';

const ZERO_WEIGHTS: PolicyWeights = {
  triageExploitabilityWeight: 0,
  triageBlastRadiusWeight: 0,
  triageEolRiskWeight: 0,
  triageSlaBreachWeight: 0,
  triageMissingOwnerBoost: 0,
  triagePatchGapBoost: 0,
};

const DOUBLE_WEIGHTS: PolicyWeights = {
  triageExploitabilityWeight: 2,
  triageBlastRadiusWeight: 2,
  triageEolRiskWeight: 2,
  triageSlaBreachWeight: 2,
  triageMissingOwnerBoost: 2,
  triagePatchGapBoost: 2,
};

function buildCve(overrides: Partial<OrgSpecificCveExposureRecord> = {}): OrgSpecificCveExposureRecord {
  return {
    recordId: 'r-1',
    vulnerabilityId: 'v-1',
    externalId: 'CVE-2024-0001',
    title: 'Test',
    applicability: 'UNKNOWN',
    impacted: false,
    impactState: 'UNKNOWN',
    severity: 'MEDIUM',
    inKev: false,
    matchedComponentCount: 0,
    matchedSoftwareCount: 0,
    matchedAssetCount: 0,
    applicableComponentCount: 0,
    impactedComponentCount: 0,
    notAffectedComponentCount: 0,
    fixedComponentCount: 0,
    noPatchComponentCount: 0,
    underInvestigationComponentCount: 0,
    unknownComponentCount: 0,
    openFindings: 0,
    eolComponentCount: 0,
    eosComponentCount: 0,
    hasInvestigationSummary: false,
    hasAiSolution: false,
    ...overrides,
  };
}

/**
 * Neutral baseline: OPEN status, owner assigned, dueAt > 30 days out.
 * Score is 0 with no overrides — each test isolates one signal.
 */
function buildFinding(overrides: Partial<Finding> = {}): Finding {
  return {
    id: 'f-1',
    displayId: 'F-1',
    componentId: 'c-1',
    assetName: 'asset',
    assetIdentifier: 'asset-1',
    assetType: 'HOST',
    packageName: 'pkg',
    packageVersion: '1.0',
    vulnerabilityId: 'v-1',
    source: 'NVD',
    creationSource: 'AUTOMATIC',
    severity: 'MEDIUM',
    inKev: false,
    riskScore: 0,
    confidenceScore: 0,
    matchedBy: 'CPE',
    evidence: '',
    firstObservedAt: '2026-01-01T00:00:00Z',
    lastObservedAt: '2026-01-01T00:00:00Z',
    decisionState: 'AFFECTED',
    status: 'OPEN',
    updatedAt: '2026-01-01T00:00:00Z',
    assignedTo: 'analyst',
    dueAt: new Date(Date.now() + 60 * 86_400_000).toISOString(),
    ...overrides,
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// riskScoreLabel + riskScoreColor — boundary tests
// ─────────────────────────────────────────────────────────────────────────────

describe('riskScoreLabel', () => {
  it('Critical at >= 9', () => {
    expect(riskScoreLabel(9)).toBe('Critical');
    expect(riskScoreLabel(10)).toBe('Critical');
    expect(riskScoreLabel(9.5)).toBe('Critical');
  });

  it('High at >= 7 and < 9', () => {
    expect(riskScoreLabel(7)).toBe('High');
    expect(riskScoreLabel(8.99)).toBe('High');
  });

  it('Medium at >= 4 and < 7', () => {
    expect(riskScoreLabel(4)).toBe('Medium');
    expect(riskScoreLabel(6.99)).toBe('Medium');
  });

  it('Low below 4', () => {
    expect(riskScoreLabel(0)).toBe('Low');
    expect(riskScoreLabel(3.99)).toBe('Low');
  });
});

describe('riskScoreColor', () => {
  it('returns critical color at >= 9', () => {
    expect(riskScoreColor(9)).toContain('critical');
  });
  it('returns high color at 7-8.99', () => {
    expect(riskScoreColor(7)).toContain('high');
  });
  it('returns medium color at 4-6.99', () => {
    expect(riskScoreColor(5)).toContain('medium');
  });
  it('returns low color below 4', () => {
    expect(riskScoreColor(2)).toContain('low');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// computeCveRiskScore — per stage
// ─────────────────────────────────────────────────────────────────────────────

describe('computeCveRiskScore — baseline', () => {
  it('returns 0 for an empty CVE with no signals', () => {
    const result = computeCveRiskScore(buildCve());
    expect(result.score).toBe(0);
    expect(result.label).toBe('Low');
    expect(result.topReasons).toEqual([]);
  });

  it('emits a CVE Published journey entry even with zero CVSS/EPSS', () => {
    const result = computeCveRiskScore(buildCve());
    expect(result.journey[0]?.stage).toBe('CVE Published');
    expect(result.journey[0]?.delta).toBe(0);
  });
});

describe('computeCveRiskScore — Stage 1 (CVSS + EPSS)', () => {
  it('CVSS 10 contributes 3.0', () => {
    const result = computeCveRiskScore(buildCve({ cvssScore: 10 }));
    expect(result.score).toBe(3);
  });

  it('CVSS 5 contributes 1.5', () => {
    const result = computeCveRiskScore(buildCve({ cvssScore: 5 }));
    expect(result.score).toBe(1.5);
  });

  it('EPSS 0.2 (20%) contributes 2.0 (capped)', () => {
    const result = computeCveRiskScore(buildCve({ epssScore: 0.2 }));
    expect(result.score).toBe(2);
  });

  it('EPSS 0.5 (50%) caps at 2.0', () => {
    const result = computeCveRiskScore(buildCve({ epssScore: 0.5 }));
    expect(result.score).toBe(2);
  });

  it('EPSS 0.05 (5%) contributes 0.5', () => {
    const result = computeCveRiskScore(buildCve({ epssScore: 0.05 }));
    expect(result.score).toBe(0.5);
  });

  it('CVSS + EPSS combine in stage 1', () => {
    const result = computeCveRiskScore(buildCve({ cvssScore: 10, epssScore: 0.2 }));
    expect(result.score).toBe(5);
  });

  it('reason includes CVSS when present, EPSS when present', () => {
    const result = computeCveRiskScore(buildCve({ cvssScore: 7.5, epssScore: 0.1 }));
    expect(result.journey[0]?.reason).toContain('CVSS 7.5');
    expect(result.journey[0]?.reason).toContain('EPSS 10.0%');
  });

  it('omits EPSS from reason when EPSS is undefined', () => {
    const result = computeCveRiskScore(buildCve({ cvssScore: 7.5 }));
    expect(result.journey[0]?.reason).toContain('CVSS 7.5');
    expect(result.journey[0]?.reason).not.toContain('EPSS');
  });

  it('shows N/A when CVSS is undefined', () => {
    const result = computeCveRiskScore(buildCve({ epssScore: 0.1 }));
    expect(result.journey[0]?.reason).toContain('CVSS N/A');
  });
});

describe('computeCveRiskScore — Stage 2 (CISA KEV)', () => {
  it('KEV adds 1.5', () => {
    const base = computeCveRiskScore(buildCve());
    const withKev = computeCveRiskScore(buildCve({ inKev: true }));
    expect(withKev.score - base.score).toBeCloseTo(1.5);
  });

  it('KEV emits a journey entry with KEV reason', () => {
    const result = computeCveRiskScore(buildCve({ inKev: true }));
    const kevEvent = result.journey.find((e) => e.stage === 'In CISA KEV');
    expect(kevEvent).toBeTruthy();
    expect(kevEvent?.reason).toContain('CISA KEV');
  });

  it('omits KEV stage when inKev is false', () => {
    const result = computeCveRiskScore(buildCve({ inKev: false }));
    expect(result.journey.find((e) => e.stage === 'In CISA KEV')).toBeUndefined();
  });
});

describe('computeCveRiskScore — Stage 3 (Org Exposure / blast radius)', () => {
  it('1 asset contributes ~0.07', () => {
    const result = computeCveRiskScore(buildCve({ matchedAssetCount: 1 }));
    expect(result.score).toBeCloseTo(0.07, 2);
  });

  it('15 assets contributes 1.0', () => {
    const result = computeCveRiskScore(buildCve({ matchedAssetCount: 15 }));
    expect(result.score).toBe(1);
  });

  it('100 assets caps at 1.5', () => {
    const result = computeCveRiskScore(buildCve({ matchedAssetCount: 100 }));
    expect(result.score).toBe(1.5);
  });

  it('singular reason for 1 asset', () => {
    const result = computeCveRiskScore(buildCve({ matchedAssetCount: 1 }));
    const event = result.journey.find((e) => e.stage === 'Org Exposure');
    expect(event?.reason).toContain('1 asset impacted');
    expect(event?.reason).not.toContain('1 assets');
  });

  it('plural reason for >1 assets', () => {
    const result = computeCveRiskScore(buildCve({ matchedAssetCount: 5 }));
    const event = result.journey.find((e) => e.stage === 'Org Exposure');
    expect(event?.reason).toContain('5 assets');
  });

  it('skips Org Exposure when no matched assets', () => {
    const result = computeCveRiskScore(buildCve({ matchedAssetCount: 0 }));
    expect(result.journey.find((e) => e.stage === 'Org Exposure')).toBeUndefined();
  });
});

describe('computeCveRiskScore — Stage 4 (EOL Risk)', () => {
  it('EOL component adds 1.0', () => {
    const result = computeCveRiskScore(buildCve({ eolComponentCount: 1 }));
    expect(result.score).toBe(1);
  });

  it('singular reason for 1 EOL component', () => {
    const result = computeCveRiskScore(buildCve({ eolComponentCount: 1 }));
    const event = result.journey.find((e) => e.stage === 'EOL Risk');
    expect(event?.reason).toContain('1 EOL component');
    expect(event?.reason).not.toContain('1 EOL components');
  });

  it('plural reason for >1 EOL components', () => {
    const result = computeCveRiskScore(buildCve({ eolComponentCount: 3 }));
    const event = result.journey.find((e) => e.stage === 'EOL Risk');
    expect(event?.reason).toContain('3 EOL components');
  });

  it('skips EOL stage when count is 0', () => {
    const result = computeCveRiskScore(buildCve({ eolComponentCount: 0 }));
    expect(result.journey.find((e) => e.stage === 'EOL Risk')).toBeUndefined();
  });
});

describe('computeCveRiskScore — Stage 5 (No Patch)', () => {
  it('No-patch component adds 1.0', () => {
    const result = computeCveRiskScore(buildCve({ noPatchComponentCount: 1 }));
    expect(result.score).toBe(1);
  });

  it('skips No Patch stage when count is 0', () => {
    const result = computeCveRiskScore(buildCve({ noPatchComponentCount: 0 }));
    expect(result.journey.find((e) => e.stage === 'No Patch')).toBeUndefined();
  });
});

describe('computeCveRiskScore — Stage 6 (Applicability)', () => {
  it('NOT_APPLICABLE reduces score by 85%', () => {
    const result = computeCveRiskScore(
      buildCve({ cvssScore: 10, epssScore: 0.2, applicability: 'NOT_APPLICABLE' })
    );
    // pre-applicability score = 5, post = 5 - 5*0.85 = 0.75
    expect(result.score).toBeCloseTo(0.75, 2);
  });

  it('NOT_APPLICABLE emits a negative-delta journey entry', () => {
    const result = computeCveRiskScore(
      buildCve({ cvssScore: 10, applicability: 'NOT_APPLICABLE' })
    );
    const event = result.journey.find((e) => e.stage === 'Not Applicable');
    expect(event).toBeTruthy();
    expect(event!.delta).toBeLessThan(0);
  });

  it('APPLICABLE with impacted components emits informational note (no score change)', () => {
    const before = computeCveRiskScore(buildCve({ cvssScore: 10 }));
    const after = computeCveRiskScore(
      buildCve({ cvssScore: 10, applicability: 'APPLICABLE', impactedComponentCount: 3 })
    );
    expect(after.score).toBe(before.score);
    const note = after.journey.find((e) => e.stage === 'Applicability Confirmed');
    expect(note?.isNote).toBe(true);
    expect(note?.delta).toBe(0);
    expect(note?.reason).toContain('3 components');
  });

  it('APPLICABLE without impacted components emits no note', () => {
    const result = computeCveRiskScore(
      buildCve({ applicability: 'APPLICABLE', impactedComponentCount: 0 })
    );
    expect(result.journey.find((e) => e.stage === 'Applicability Confirmed')).toBeUndefined();
  });

  it('UNKNOWN applicability emits no applicability stage', () => {
    const result = computeCveRiskScore(buildCve({ applicability: 'UNKNOWN' }));
    expect(result.journey.find((e) => e.stage === 'Not Applicable')).toBeUndefined();
    expect(result.journey.find((e) => e.stage === 'Applicability Confirmed')).toBeUndefined();
  });
});

describe('computeCveRiskScore — Stage 7 (Findings Created)', () => {
  it('emits informational note when openFindings > 0', () => {
    const result = computeCveRiskScore(buildCve({ openFindings: 2 }));
    const note = result.journey.find((e) => e.stage === 'Findings Created');
    expect(note?.isNote).toBe(true);
    expect(note?.delta).toBe(0);
    expect(note?.reason).toContain('2 findings');
  });

  it('emits singular when openFindings is 1', () => {
    const result = computeCveRiskScore(buildCve({ openFindings: 1 }));
    const note = result.journey.find((e) => e.stage === 'Findings Created');
    expect(note?.reason).toContain('1 finding raised');
  });

  it('skips Findings Created when openFindings is 0', () => {
    const result = computeCveRiskScore(buildCve({ openFindings: 0 }));
    expect(result.journey.find((e) => e.stage === 'Findings Created')).toBeUndefined();
  });
});

describe('computeCveRiskScore — capping and combining', () => {
  it('caps the final score at 10', () => {
    const result = computeCveRiskScore(
      buildCve({
        cvssScore: 10,
        epssScore: 0.5,
        inKev: true,
        matchedAssetCount: 100,
        eolComponentCount: 5,
        noPatchComponentCount: 5,
      })
    );
    expect(result.score).toBe(10);
    expect(result.label).toBe('Critical');
  });

  it('topReasons captures up to 3 contributors', () => {
    const result = computeCveRiskScore(
      buildCve({ cvssScore: 9, epssScore: 0.2, inKev: true, matchedAssetCount: 30 })
    );
    expect(result.topReasons.length).toBeLessThanOrEqual(3);
  });

  it('does not push topReasons for stages with zero delta', () => {
    const result = computeCveRiskScore(buildCve());
    expect(result.topReasons).toEqual([]);
  });
});

describe('computeCveRiskScore — policy weights', () => {
  it('zero exploitability weight zeros EPSS and KEV contributions', () => {
    const result = computeCveRiskScore(
      buildCve({ cvssScore: 0, epssScore: 0.5, inKev: true }),
      ZERO_WEIGHTS
    );
    expect(result.score).toBe(0);
  });

  it('zero blast-radius weight zeros asset contribution', () => {
    const result = computeCveRiskScore(
      buildCve({ matchedAssetCount: 100 }),
      ZERO_WEIGHTS
    );
    expect(result.score).toBe(0);
  });

  it('zero EOL weight zeros EOL contribution', () => {
    const result = computeCveRiskScore(
      buildCve({ eolComponentCount: 5 }),
      ZERO_WEIGHTS
    );
    expect(result.score).toBe(0);
  });

  it('zero patch-gap weight zeros no-patch contribution', () => {
    const result = computeCveRiskScore(
      buildCve({ noPatchComponentCount: 5 }),
      ZERO_WEIGHTS
    );
    expect(result.score).toBe(0);
  });

  it('double weights amplify each weighted signal', () => {
    const single = computeCveRiskScore(buildCve({ inKev: true }));
    const doubled = computeCveRiskScore(buildCve({ inKev: true }), DOUBLE_WEIGHTS);
    expect(doubled.score).toBeCloseTo(single.score * 2, 1);
  });

  it('partial policy override merges with defaults', () => {
    const result = computeCveRiskScore(
      buildCve({ inKev: true, eolComponentCount: 1 }),
      { triageEolRiskWeight: 0 } as PolicyWeights
    );
    // KEV: 1.5 (default weight 1), EOL: 0 (zero weight) → 1.5
    expect(result.score).toBe(1.5);
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// computeFindingPriorityScore — per signal
// ─────────────────────────────────────────────────────────────────────────────

const ONE_DAY_MS = 86_400_000;

function isoOffsetDays(days: number): string {
  return new Date(Date.now() + days * ONE_DAY_MS).toISOString();
}

describe('computeFindingPriorityScore — exploitability', () => {
  it('KEV adds 3.0', () => {
    const result = computeFindingPriorityScore(buildFinding({ inKev: true }));
    expect(result.score).toBe(3);
    expect(result.topReasons.some((r) => r.includes('CISA'))).toBe(true);
  });

  it('EPSS >= 0.5 adds 2.5 when not KEV', () => {
    const result = computeFindingPriorityScore(buildFinding({ epss: 0.6 }));
    expect(result.score).toBe(2.5);
    expect(result.topReasons.some((r) => r.includes('Very high EPSS'))).toBe(true);
  });

  it('EPSS 0.1 (10%) contributes 1.5 with reason', () => {
    const result = computeFindingPriorityScore(buildFinding({ epss: 0.1 }));
    expect(result.score).toBe(1.5);
    expect(result.topReasons.some((r) => r.includes('EPSS 10.0%'))).toBe(true);
  });

  it('EPSS 0.01 contributes 0.15 without reason', () => {
    const result = computeFindingPriorityScore(buildFinding({ epss: 0.01 }));
    expect(result.score).toBeCloseTo(0.15, 2);
    expect(result.topReasons.some((r) => r.includes('EPSS'))).toBe(false);
  });

  it('KEV trumps EPSS branch', () => {
    const result = computeFindingPriorityScore(buildFinding({ inKev: true, epss: 0.99 }));
    // Only +3.0 from KEV branch, NOT +2.5 from very-high-EPSS branch
    expect(result.score).toBe(3);
  });
});

describe('computeFindingPriorityScore — SLA breach proximity', () => {
  it('breached SLA (negative days) adds 2.5', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ dueAt: isoOffsetDays(-3) })
    );
    expect(result.score).toBe(2.5);
    expect(result.topReasons.some((r) => r.includes('breached'))).toBe(true);
  });

  it('SLA in 1 day adds 2.0', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ dueAt: isoOffsetDays(2) })
    );
    expect(result.score).toBe(2);
  });

  it('SLA in 5 days adds 1.5', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ dueAt: isoOffsetDays(5) })
    );
    expect(result.score).toBe(1.5);
  });

  it('SLA in 10 days adds 1.0 (no reason)', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ dueAt: isoOffsetDays(10) })
    );
    expect(result.score).toBe(1);
    expect(result.topReasons.length).toBe(0);
  });

  it('SLA in 20 days adds 0.5 (no reason)', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ dueAt: isoOffsetDays(20) })
    );
    expect(result.score).toBe(0.5);
  });

  it('SLA beyond 30 days adds 0', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ dueAt: isoOffsetDays(60) })
    );
    expect(result.score).toBe(0);
  });

  it('OPEN finding without dueAt adds 0.3 with reason', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ status: 'OPEN', dueAt: undefined })
    );
    expect(result.score).toBeCloseTo(0.3, 2);
    expect(result.topReasons.some((r) => r.includes('No SLA'))).toBe(true);
  });
});

describe('computeFindingPriorityScore — ownership', () => {
  it('no owner anywhere adds 1.5', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ assignedTo: undefined })
    );
    expect(result.score).toBe(1.5);
    expect(result.topReasons.some((r) => r.includes('No owner'))).toBe(true);
  });

  it('ownership.displayName but no assignedTo adds 0.5', () => {
    const result = computeFindingPriorityScore(
      buildFinding({
        assignedTo: undefined,
        ownership: { displayName: 'Alice', sourceType: 'CMDB' } as Finding['ownership'],
      })
    );
    expect(result.score).toBe(0.5);
  });

  it('assignedTo present skips both ownership branches', () => {
    const result = computeFindingPriorityScore(buildFinding());
    expect(result.score).toBe(0);
  });
});

describe('computeFindingPriorityScore — EOL', () => {
  it('isEol with negative days reports days-ago', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ isEol: true, eolDaysRemaining: -30 })
    );
    expect(result.score).toBe(1.5);
    expect(result.topReasons.some((r) => r.includes('30d ago'))).toBe(true);
  });

  it('isEol without days reports generic message', () => {
    const result = computeFindingPriorityScore(buildFinding({ isEol: true }));
    expect(result.score).toBe(1.5);
    expect(result.topReasons.some((r) => r.includes('EOL component affected'))).toBe(true);
  });

  it('isEol with positive days remaining still reports affected', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ isEol: true, eolDaysRemaining: 30 })
    );
    expect(result.topReasons.some((r) => r.includes('EOL component affected'))).toBe(true);
  });
});

describe('computeFindingPriorityScore — severity', () => {
  it('CRITICAL adds 1.0', () => {
    const result = computeFindingPriorityScore(buildFinding({ severity: 'CRITICAL' }));
    expect(result.score).toBe(1);
  });

  it('HIGH adds 0.5', () => {
    const result = computeFindingPriorityScore(buildFinding({ severity: 'HIGH' }));
    expect(result.score).toBe(0.5);
  });

  it('MEDIUM adds 0', () => {
    const result = computeFindingPriorityScore(buildFinding({ severity: 'MEDIUM' }));
    expect(result.score).toBe(0);
  });
});

describe('computeFindingPriorityScore — VEX', () => {
  it('VEX AFFECTED adds 0.5', () => {
    const result = computeFindingPriorityScore(buildFinding({ vexStatus: 'AFFECTED' }));
    expect(result.score).toBe(0.5);
    expect(result.topReasons.some((r) => r.includes('VEX'))).toBe(true);
  });

  it('VEX other statuses add 0', () => {
    const result = computeFindingPriorityScore(buildFinding({ vexStatus: 'NOT_AFFECTED' }));
    expect(result.score).toBe(0);
  });
});

describe('computeFindingPriorityScore — status modifier', () => {
  it('non-OPEN status reduces final score to 10%', () => {
    const open = computeFindingPriorityScore(
      buildFinding({ status: 'OPEN', inKev: true })
    );
    const resolved = computeFindingPriorityScore(
      buildFinding({ status: 'RESOLVED', inKev: true })
    );
    expect(resolved.score).toBeCloseTo(open.score * 0.1, 2);
  });

  it('SUPPRESSED also reduces to 10%', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ status: 'SUPPRESSED', inKev: true })
    );
    expect(result.score).toBe(0.3);
  });
});

describe('computeFindingPriorityScore — capping and policy weights', () => {
  it('caps the final score at 10', () => {
    const result = computeFindingPriorityScore(
      buildFinding({
        status: 'OPEN',
        inKev: true,
        epss: 0.99,
        dueAt: isoOffsetDays(-30),
        assignedTo: undefined,
        isEol: true,
        eolDaysRemaining: -100,
        severity: 'CRITICAL',
        vexStatus: 'AFFECTED',
      })
    );
    expect(result.score).toBe(10);
    expect(result.label).toBe('Critical');
  });

  it('zero exploitability weight zeros KEV contribution', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ inKev: true, assignedTo: 'a' }),
      ZERO_WEIGHTS
    );
    expect(result.score).toBe(0);
  });

  it('zero SLA weight zeros breach contribution', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ dueAt: isoOffsetDays(-10), assignedTo: 'a' }),
      ZERO_WEIGHTS
    );
    expect(result.score).toBe(0);
  });

  it('zero owner weight zeros missing-owner contribution', () => {
    const result = computeFindingPriorityScore(
      buildFinding({ status: 'AUTO_CLOSED' }),
      ZERO_WEIGHTS
    );
    expect(result.score).toBe(0);
  });

  it('topReasons capped at 3', () => {
    const result = computeFindingPriorityScore(
      buildFinding({
        status: 'OPEN',
        inKev: true,
        dueAt: isoOffsetDays(-1),
        isEol: true,
        vexStatus: 'AFFECTED',
        severity: 'CRITICAL',
      })
    );
    expect(result.topReasons.length).toBeLessThanOrEqual(3);
  });
});

// ── computeOrgImpact ──────────────────────────────────────────────────────────

describe('computeOrgImpact', () => {
  function baseItem(overrides: Partial<OrgSpecificCveExposureRecord> = {}): OrgSpecificCveExposureRecord {
    return buildCve({ matchedAssetCount: 1, cvssScore: 5.0, epssScore: 0, inKev: false, ...overrides });
  }

  it('returns NONE when matchedAssetCount is 0', () => {
    expect(computeOrgImpact(baseItem({ matchedAssetCount: 0 }), 5, 0)).toBe('NONE');
  });

  it('returns HIGH when cvss >= 9.0 (critical)', () => {
    expect(computeOrgImpact(baseItem({ cvssScore: 9.0 }), 5, 0)).toBe('HIGH');
  });

  it('returns HIGH when inKev is true', () => {
    expect(computeOrgImpact(baseItem({ inKev: true }), 5, 0)).toBe('HIGH');
  });

  it('returns HIGH when epss >= 0.3', () => {
    expect(computeOrgImpact(baseItem({ epssScore: 0.3 }), 5, 0)).toBe('HIGH');
  });

  it('returns HIGH when saiScore exceeds cvss by more than 1', () => {
    expect(computeOrgImpact(baseItem({ cvssScore: 5.0 }), 7.0, 0)).toBe('HIGH');
  });

  it('returns HIGH when externalFacingCount > 0', () => {
    expect(computeOrgImpact(baseItem({ cvssScore: 5.0 }), 5.0, 1)).toBe('HIGH');
  });

  it('returns MEDIUM when saiScore is within ±1 of cvss and no HIGH conditions apply', () => {
    // cvss=5.0, saiScore=5.5 → |5.5-5.0|=0.5 ≤ 1.0 → MEDIUM
    expect(computeOrgImpact(baseItem({ cvssScore: 5.0 }), 5.5, 0)).toBe('MEDIUM');
  });

  it('returns LOW when saiScore is more than 1 below cvss and no HIGH conditions apply', () => {
    // cvss=5.0, saiScore=3.0 → |3.0-5.0|=2.0 > 1.0, saiScore < cvss+1 → LOW
    expect(computeOrgImpact(baseItem({ cvssScore: 5.0 }), 3.0, 0)).toBe('LOW');
  });
});
