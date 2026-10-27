import React from 'react';
import { useActor } from '../features/auth/context';
import { canUseEntitlement } from '../features/auth/entitlements';
import type { InvestigationSummaryResponse } from '../features/cve-workbench/types';
import {
  Document,
  HeadingLevel,
  Packer,
  Paragraph,
  Table,
  TableCell,
  TableRow,
  TextRun,
  WidthType,
} from 'docx';
import { resolveApiBase } from '../api/base';

const deterministicLocalKey = (cveId: string) => `vulnrepo:${cveId}:det-summary`;
const aiLocalKey = (cveId: string) => `vulnrepo:${cveId}:ai-summary`;

const COLORS = {
  background: 'var(--dp-surface-2)',
  surface: 'var(--dp-surface)',
  surfaceMuted: 'color-mix(in srgb, var(--dp-surface-2) 88%, var(--dp-bg))',
  accent: 'var(--dp-accent)',
  accentStrong: 'color-mix(in srgb, var(--dp-accent) 85%, var(--dp-text))',
  text: 'var(--dp-text)',
  title: 'var(--dp-text)',
  muted: 'var(--dp-text-2)',
  danger: 'var(--dp-critical)',
  warning: 'var(--dp-high)',
  caution: 'var(--dp-medium)',
  success: 'var(--dp-low)',
  border: 'var(--dp-border)',
  borderStrong: 'var(--dp-border-strong)',
  track: 'var(--dp-hover)',
};

const API_BASE = resolveApiBase();
const API_KEY = import.meta.env.DEV ? (import.meta.env.VITE_API_KEY ?? 'change-me-in-prod') : '';
const CREATOR_KEY = import.meta.env.DEV ? (import.meta.env.VITE_CREATOR_KEY ?? 'local-creator') : '';

const LOADING_STEPS = [
  'Analyzing 4 runbook results...',
  'Cross-referencing asset exposure...',
  'Generating remediation plan...',
];

export type InvestigationSummaryInput = {
  summary: {
    cveId: string;
    title: string;
    description?: string;
    severity: string;
    cvssScore?: number;
    epssScore?: number;
    inKev?: boolean;
    exploitAvailable?: boolean;
    patchAvailable?: boolean;
    patchVersions?: string;
  };
  investigation: {
    leadAnalyst?: string;
  };
  runbookResults: Array<{
    id: string;
    title: string;
    state: string;
  }>;
  affectedAssets: Array<{
    id: string;
    hostname: string;
    ipAddress?: string;
    os?: string;
    owner?: string;
    environment?: string;
    externalFacing?: boolean;
    critical?: boolean;
    matchedSoftware: Array<{
      software: string;
      version?: string;
    }>;
  }>;
  falsePositiveRows: Array<{
    software: string;
    version?: string;
    falsePositive: boolean;
    assetsNotImpacted?: number;
    vendorAdvisory?: string;
    vendorGuidance?: string;
  }>;
  eolRows: Array<{
    software: string;
    vendor?: string;
    version?: string;
    lifecycle?: string;
    endOfSupport?: string;
    endOfLife?: string;
    recommendedUpgrade?: string;
  }>;
  solutionRows?: Array<{
    software: string;
    version?: string;
    vendor?: string;
    impactedAssets?: number;
    solutionType?: string;
    solutionDetail?: string;
    targetVersion?: string;
  }>;
  createdFindings?: Array<{
    displayId: string;
    assetName: string;
    assetIdentifier: string;
    packageName: string;
    packageVersion: string;
    severity: string;
    status: string;
    decisionState: string;
    assignedTo?: string;
    dueAt?: string;
    incidentId?: string;
  }>;
};

type SummaryMode = 'deterministic' | 'ai';

type Props = {
  visible: boolean;
  input: InvestigationSummaryInput;
  initialSummary?: InvestigationSummaryResponse | null;
  initialMode?: SummaryMode;
  autoGenerate?: boolean;
  readOnly?: boolean;
};

function severityColor(severity: string): string {
  const normalized = severity.toUpperCase();
  if (normalized === 'CRITICAL') return COLORS.danger;
  if (normalized === 'HIGH') return COLORS.warning;
  if (normalized === 'MEDIUM') return COLORS.caution;
  return COLORS.success;
}

function timeframeColor(timeframe: string): string {
  const normalized = timeframe.toLowerCase();
  if (normalized.includes('immediate')) return COLORS.danger;
  if (normalized.includes('short')) return COLORS.warning;
  if (normalized.includes('medium')) return COLORS.caution;
  return COLORS.success;
}

function formatDateTime(value?: string): string {
  if (!value) return '—';
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime())) return value;
  return parsed.toLocaleString();
}

function riskMeterGradient(score: number): string {
  if (score >= 85) return `linear-gradient(90deg, ${COLORS.danger}, color-mix(in srgb, ${COLORS.danger} 62%, white))`;
  if (score >= 70) return `linear-gradient(90deg, ${COLORS.warning}, color-mix(in srgb, ${COLORS.warning} 58%, white))`;
  if (score >= 45) return `linear-gradient(90deg, ${COLORS.caution}, color-mix(in srgb, ${COLORS.caution} 58%, white))`;
  return `linear-gradient(90deg, ${COLORS.success}, color-mix(in srgb, ${COLORS.success} 60%, white))`;
}

function tonedSurface(color: string, strength = 14): string {
  return `color-mix(in srgb, ${color} ${strength}%, var(--dp-surface-2))`;
}

function tonedBorder(color: string, strength = 26): string {
  return `color-mix(in srgb, ${color} ${strength}%, var(--dp-border))`;
}

function buildDeterministicSummary(input: InvestigationSummaryInput): InvestigationSummaryResponse {
  const { summary, affectedAssets, falsePositiveRows, eolRows, createdFindings = [] } = input;
  const totalAffected = affectedAssets.length;
  const falsePositives = falsePositiveRows.filter((r) => r.falsePositive).length;
  const truePositives = totalAffected - falsePositives;
  const externalFacing = affectedAssets.filter((a) => a.externalFacing).length;
  const internalAssetCount = totalAffected - externalFacing;
  const eolAtRisk = eolRows.filter((r) => r.lifecycle && r.lifecycle.toLowerCase() !== 'supported' && r.lifecycle.toLowerCase() !== 'unknown').length;
  const createdFindingCount = createdFindings.length;
  const unpatchedVulnerable = summary.patchAvailable ? truePositives : 0;
  const sev = summary.severity.toUpperCase();
  const cvss = summary.cvssScore ?? 0;
  const score = Math.round(Math.min(100, cvss * 10 + (summary.inKev ? 5 : 0) + (summary.exploitAvailable ? 3 : 0)));

  const executiveSummary = [
    `${summary.cveId} is currently assessed as ${sev.toLowerCase()} risk.`,
    `The investigation identified ${totalAffected} impacted asset${totalAffected !== 1 ? 's' : ''}, including ${externalFacing} external-facing system${externalFacing !== 1 ? 's' : ''}.`,
    `${truePositives} asset${truePositives !== 1 ? 's' : ''} remain true positive${truePositives !== 1 ? 's' : ''} after vendor-advisory review, while ${falsePositives} asset${falsePositives !== 1 ? 's' : ''} were cleared as false positive${falsePositives !== 1 ? 's' : ''}.`,
    createdFindingCount > 0
      ? `${createdFindingCount} finding${createdFindingCount === 1 ? ' was' : 's were'} created during the investigation workflow and ${createdFindingCount === 1 ? 'is' : 'are'} included in the report.`
      : null,
    eolAtRisk > 0
      ? `${eolAtRisk} software version${eolAtRisk !== 1 ? 's' : ''} carry end-of-life risk, and the recommended remediation path is to prioritize containment, patching, and lifecycle upgrades in that order.`
      : `No end-of-life software risk was identified. The recommended remediation path is to apply the available patch as soon as possible.`,
  ].join(' ');

  const riskRationale = [
    `CVSS score of ${cvss.toFixed(1)} indicates ${sev.toLowerCase()} severity.`,
    summary.inKev ? 'This vulnerability is listed in the CISA Known Exploited Vulnerabilities catalog.' : null,
    summary.exploitAvailable ? 'Public exploit code is available.' : null,
    summary.patchAvailable ? `A patch is available (${summary.patchVersions ?? 'see vendor advisory'}).` : 'No vendor patch is currently available.',
    externalFacing > 0 ? `${externalFacing} internet-facing asset${externalFacing !== 1 ? 's' : ''} increase exposure.` : null,
  ].filter(Boolean).join(' ');

  const remediationPlan = [];
  if (summary.patchAvailable) {
    remediationPlan.push({
      priority: 1, priorityLabel: 'P1',
      title: 'Apply vendor patch',
      detail: `Patch all ${truePositives} confirmed impacted asset${truePositives !== 1 ? 's' : ''} to ${summary.patchVersions ?? 'the latest patched release'}.`,
      owner: 'IT Operations', timeframe: externalFacing > 0 ? 'Immediate (24–48 hours)' : 'Short-term (1–2 weeks)', type: 'PATCH',
    });
  } else {
    remediationPlan.push({
      priority: 1, priorityLabel: 'P1',
      title: 'Apply compensating controls',
      detail: 'No vendor patch is currently available. Apply network segmentation, WAF rules, or disable the affected component until a patch is released.',
      owner: 'Security Operations', timeframe: 'Immediate (24–48 hours)', type: 'MITIGATE',
    });
  }
  if (externalFacing > 0) {
    remediationPlan.push({
      priority: 2, priorityLabel: 'P2',
      title: 'Isolate external-facing assets',
      detail: `${externalFacing} internet-facing asset${externalFacing !== 1 ? 's' : ''} should be prioritized and isolated if patching cannot be completed immediately.`,
      owner: 'Network Security', timeframe: 'Immediate (24–48 hours)', type: 'CONTAIN',
    });
  }
  if (eolAtRisk > 0) {
    const eolSoftware = eolRows.filter((r) => r.lifecycle && r.lifecycle.toLowerCase() !== 'supported' && r.lifecycle.toLowerCase() !== 'unknown').map((r) => r.software).join(', ');
    remediationPlan.push({
      priority: remediationPlan.length + 1, priorityLabel: `P${remediationPlan.length + 1}`,
      title: 'Address end-of-life software',
      detail: `Upgrade or replace end-of-life software: ${eolSoftware}. EOL products no longer receive security updates and increase long-term exposure.`,
      owner: 'IT Operations', timeframe: 'Medium-term (30–90 days)', type: 'UPGRADE',
    });
  }
  const keyFindings: string[] = [];
  keyFindings.push(`${totalAffected} asset${totalAffected !== 1 ? 's' : ''} matched CVE criteria; ${truePositives} confirmed true positive${truePositives !== 1 ? 's' : ''}.`);
  if (externalFacing > 0) keyFindings.push(`${externalFacing} external-facing asset${externalFacing !== 1 ? 's' : ''} at elevated risk of exploitation.`);
  if (summary.inKev) keyFindings.push('Actively exploited in the wild (CISA KEV listing).');
  if (eolAtRisk > 0) keyFindings.push(`${eolAtRisk} software version${eolAtRisk !== 1 ? 's' : ''} are end-of-life and should be prioritized for upgrade.`);
  if (falsePositives > 0) keyFindings.push(`${falsePositives} asset${falsePositives !== 1 ? 's' : ''} cleared as false positives based on vendor advisory.`);
  if (!summary.patchAvailable) keyFindings.push('No vendor patch available — compensating controls required.');
  if (createdFindingCount > 0) {
    const sampleFindings = createdFindings.slice(0, 3).map((finding) => {
      const bits = [
        finding.displayId,
        finding.assetName || finding.assetIdentifier,
        finding.packageName,
        finding.packageVersion || '—',
        finding.severity,
      ].filter(Boolean);
      return bits.join(' · ');
    });
    keyFindings.push(
      `${createdFindingCount} finding${createdFindingCount !== 1 ? 's' : ''} created: ${sampleFindings.join('; ')}${createdFindingCount > sampleFindings.length ? '…' : ''}`
    );
  }
  remediationPlan.push({
    priority: remediationPlan.length + 1, priorityLabel: `P${remediationPlan.length + 1}`,
    title: 'Validate remediation and close findings',
    detail: 'Re-scan patched systems to confirm remediation and close associated findings in the vulnerability tracking system.',
    owner: 'Security Operations', timeframe: 'Short-term (1–2 weeks)', type: 'VALIDATE',
  });

  return {
    generatedAt: new Date().toISOString(),
    executiveSummary,
    riskAnalysis: { level: sev, score, rationale: riskRationale },
    impactAnalysis: {
      externalFacingCount: externalFacing,
      internalAssetCount,
      falsePositiveSummary: falsePositives > 0
        ? `${falsePositives} software entr${falsePositives !== 1 ? 'ies' : 'y'} confirmed not impacted per vendor VEX advisory.`
        : 'No false positives identified; all matched software confirmed impacted.',
      eolRiskSummary: eolAtRisk > 0
        ? `${eolAtRisk} software version${eolAtRisk !== 1 ? 's' : ''} are at end-of-life and no longer receive security patches.`
        : 'No end-of-life software risk identified.',
      patchGapSummary: summary.patchAvailable
        ? `Vendor patch available: ${summary.patchVersions ?? 'see vendor advisory'}. Apply to all ${truePositives} impacted asset${truePositives !== 1 ? 's' : ''}.`
        : 'No vendor patch available. Monitor vendor advisory for patch release.',
    },
    remediationPlan,
    keyFindings,
    metrics: { totalAffected, truePositives, falsePositives, externalFacing, unpatchedVulnerable, eolCount: eolAtRisk },
  };
}

async function generateSummaryRequest(
  input: InvestigationSummaryInput,
  mode: SummaryMode
): Promise<{ summary?: InvestigationSummaryResponse; rawText?: string; error?: string }> {
  // Deterministic mode: compute entirely on the frontend — no API call, instant result.
  if (mode === 'deterministic') {
    return { summary: buildDeterministicSummary(input) };
  }

  const headers = new Headers();
  headers.set('Content-Type', 'application/json');
  if (API_KEY.trim().length > 0) headers.set('X-API-Key', API_KEY.trim());
  if (CREATOR_KEY.trim().length > 0) headers.set('X-Creator-Key', CREATOR_KEY);

  try {
    const response = await fetch(`${API_BASE}/cve-detail/${encodeURIComponent(input.summary.cveId)}/investigation-ai-summary`, {
      method: 'POST',
      headers,
      body: JSON.stringify(input),
    });

    if (!response.ok) {
      const text = await response.text();
      return { error: text || `Request failed (${response.status})` };
    }

    const contentType = response.headers.get('content-type') ?? '';
    if (!contentType.includes('application/json')) {
      return { rawText: await response.text() };
    }

    return { summary: await response.json() as InvestigationSummaryResponse };
  } catch (error) {
    return { error: error instanceof Error ? error.message : String(error) };
  }
}

/** Convert markdown lines to docx Paragraph children for Word export */
function markdownToDocxParagraphs(md: string): Paragraph[] {
  const paras: Paragraph[] = [];
  const lines = md.split('\n');
  for (const line of lines) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    if (/^### (.+)$/.test(trimmed)) {
      paras.push(new Paragraph({ text: trimmed.replace(/^### /, ''), heading: HeadingLevel.HEADING_3 }));
    } else if (/^## (.+)$/.test(trimmed)) {
      paras.push(new Paragraph({ text: trimmed.replace(/^## /, ''), heading: HeadingLevel.HEADING_2 }));
    } else if (/^# (.+)$/.test(trimmed)) {
      paras.push(new Paragraph({ text: trimmed.replace(/^# /, ''), heading: HeadingLevel.HEADING_1 }));
    } else if (/^---+$/.test(trimmed)) {
      paras.push(new Paragraph({ text: '─'.repeat(40) }));
    } else if (/^[-*] (.+)$/.test(trimmed)) {
      paras.push(new Paragraph({ text: trimmed.replace(/^[-*] /, ''), bullet: { level: 0 } }));
    } else if (/^\d+\. (.+)$/.test(trimmed)) {
      paras.push(new Paragraph({ text: trimmed.replace(/^\d+\. /, '') }));
    } else if (/^\|.+\|$/.test(trimmed)) {
      // Skip table separator rows; render others as plain text
      if (!/^\|[\s|:-]+\|$/.test(trimmed)) {
        const cells = trimmed.slice(1, -1).split('|').map((c) => c.trim()).join(' | ');
        paras.push(new Paragraph({ children: [new TextRun({ text: cells, font: 'Courier New', size: 18 })] }));
      }
    } else {
      const text = trimmed.replace(/\*\*(.+?)\*\*/g, '$1');
      paras.push(new Paragraph(text));
    }
  }
  return paras;
}

async function exportWordDocument(
  input: InvestigationSummaryInput,
  summary: InvestigationSummaryResponse,
  mode: SummaryMode
): Promise<void> {
  let bodyChildren: (Paragraph | Table)[];

  if (mode === 'ai' && summary.markdownReport) {
    // Export the AI markdown report as structured Word paragraphs
    bodyChildren = [
      new Paragraph({
        text: `CVE Investigation Summary — ${input.summary.cveId}`,
        heading: HeadingLevel.TITLE,
      }),
      new Paragraph(`Date generated: ${formatDateTime(summary.generatedAt)}`),
      new Paragraph(`CVSS: ${input.summary.cvssScore ?? '—'}   Severity: ${input.summary.severity}   Mode: AI Summary`),
      ...markdownToDocxParagraphs(summary.markdownReport),
      new Paragraph('Generated by T-Hub CVE Investigation Runbook'),
    ];
  } else {
    // Export the deterministic structured summary
    const externalAssets = input.affectedAssets.filter((asset) => asset.externalFacing);
    const internalAssetCount = Math.max(0, input.affectedAssets.length - externalAssets.length);
    const falsePositiveRows = input.falsePositiveRows.filter((row) => row.falsePositive);
    const eolRows = input.eolRows.filter((row) => (row.lifecycle ?? '').toLowerCase() !== 'supported');
    const createdFindings = input.createdFindings ?? [];

    bodyChildren = [
      new Paragraph({
        text: `CVE Investigation Summary — ${input.summary.cveId}`,
        heading: HeadingLevel.TITLE,
      }),
      new Paragraph(`Date generated: ${formatDateTime(summary.generatedAt)}`),
      new Paragraph(`CVSS: ${input.summary.cvssScore ?? '—'}   Severity: ${input.summary.severity}   Mode: Deterministic Summary`),
      new Paragraph({ text: 'Executive Summary', heading: HeadingLevel.HEADING_1 }),
      new Paragraph(summary.executiveSummary),
      new Paragraph({ text: 'Impact Analysis', heading: HeadingLevel.HEADING_1 }),
      new Paragraph(`Risk: ${summary.riskAnalysis.level} (${summary.riskAnalysis.score})`),
      new Paragraph(summary.riskAnalysis.rationale),
      new Paragraph({ text: 'External-Facing Assets', heading: HeadingLevel.HEADING_2 }),
      buildTable([
        ['Hostname', 'IP', 'OS', 'Owner', 'Environment'],
        ...externalAssets.map((asset) => [asset.hostname, asset.ipAddress || '—', asset.os || '—', asset.owner || '—', asset.environment || '—']),
      ]),
      new Paragraph({ text: 'Internal Assets', heading: HeadingLevel.HEADING_2 }),
      new Paragraph(`Internal asset count: ${internalAssetCount}`),
      new Paragraph({ text: 'False Positives', heading: HeadingLevel.HEADING_2 }),
      buildTable([
        ['Asset / Software', 'Vendor advisory', 'Reason', 'Confidence'],
        ...falsePositiveRows.map((row) => [row.software, row.vendorAdvisory || '—', row.vendorGuidance || 'Vendor guidance matched', 'High']),
      ]),
      new Paragraph({ text: 'Created Findings', heading: HeadingLevel.HEADING_2 }),
      createdFindings.length > 0
        ? buildTable([
            ['Finding', 'Asset', 'Software', 'Version', 'Severity', 'Status', 'Assignee'],
            ...createdFindings.map((finding) => [
              finding.displayId,
              finding.assetName || finding.assetIdentifier || '—',
              finding.packageName,
              finding.packageVersion || '—',
              finding.severity,
              finding.status,
              finding.assignedTo || '—',
            ]),
          ])
        : new Paragraph('No findings were created during this investigation.'),
      new Paragraph({ text: 'End-of-Life Assets', heading: HeadingLevel.HEADING_2 }),
      buildTable([
        ['Hostname / Software', 'Product Version', 'EOL Date', 'Status'],
        ...eolRows.map((row) => [row.software, row.version || '—', row.endOfLife || '—', row.lifecycle || '—']),
      ]),
      new Paragraph({ text: 'Patch Compliance', heading: HeadingLevel.HEADING_2 }),
      new Paragraph(`Patched vs unpatched: ${input.summary.patchAvailable ? 'Patch available' : 'Patch unavailable'}; unpatched vulnerable assets: ${summary.metrics.unpatchedVulnerable}`),
      new Paragraph({ text: 'Remediation Plan', heading: HeadingLevel.HEADING_1 }),
      ...summary.remediationPlan.map((action) => new Paragraph(`${action.priority}. ${action.title} — ${action.detail} [${action.owner}; ${action.timeframe}]`)),
      new Paragraph({ text: 'Key Findings', heading: HeadingLevel.HEADING_1 }),
      ...summary.keyFindings.map((finding) => new Paragraph({ text: finding, bullet: { level: 0 } })),
      new Paragraph({ text: 'Metrics Summary', heading: HeadingLevel.HEADING_1 }),
      buildTable([
        ['Total Affected', 'True Positives', 'False Positives', 'External Facing', 'Unpatched Vulnerable', 'EOL Count'],
        [
          String(summary.metrics.totalAffected),
          String(summary.metrics.truePositives),
          String(summary.metrics.falsePositives),
          String(summary.metrics.externalFacing),
          String(summary.metrics.unpatchedVulnerable),
          String(summary.metrics.eolCount),
        ],
      ]),
      new Paragraph('Generated by T-Hub CVE Investigation Runbook'),
    ];
  }

  const doc = new Document({ sections: [{ children: bodyChildren }] });
  const blob = await Packer.toBlob(doc);
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.href = url;
  link.download = `${input.summary.cveId}-investigation-summary.docx`;
  document.body.appendChild(link);
  link.click();
  link.remove();
  URL.revokeObjectURL(url);
}

function buildTable(rows: string[][]): Table {
  return new Table({
    width: { size: 100, type: WidthType.PERCENTAGE },
    rows: rows.map((row, rowIndex) => new TableRow({
      children: row.map((cell) => new TableCell({
        width: { size: 100 / row.length, type: WidthType.PERCENTAGE },
        children: [
          new Paragraph({
            children: [
              new TextRun({
                text: cell,
                bold: rowIndex === 0,
              }),
            ],
          }),
        ],
      })),
    })),
  });
}

function renderMarkdown(md: string): string {
  // Process tables first: collect multi-line table blocks
  const lines = md.split('\n');
  const out: string[] = [];
  let i = 0;
  while (i < lines.length) {
    const line = lines[i];
    // Detect start of a markdown table (line starts and ends with |)
    if (/^\|.+\|$/.test(line.trim())) {
      const tableLines: string[] = [];
      while (i < lines.length && /^\|.+\|$/.test(lines[i].trim())) {
        tableLines.push(lines[i]);
        i++;
      }
      // First row = header, second row = separator (skip), rest = body
      const rows = tableLines.filter((r) => !/^\|[\s|:-]+\|$/.test(r.trim()));
      if (rows.length === 0) continue;
      const toTr = (row: string, tag: 'th' | 'td') => {
        const cells = row.trim().slice(1, -1).split('|')
          .map((c) => `<${tag}>${c.trim().replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>')}</${tag}>`)
          .join('');
        return `<tr>${cells}</tr>`;
      };
      let html = '<table class="md-table"><thead>' + toTr(rows[0], 'th') + '</thead>';
      if (rows.length > 1) {
        html += '<tbody>' + rows.slice(1).map((r) => toTr(r, 'td')).join('') + '</tbody>';
      }
      html += '</table>';
      out.push(html);
    } else {
      out.push(line);
      i++;
    }
  }
  let result = out.join('\n');

  // Headings
  result = result.replace(/^### (.+)$/gm, '<h3>$1</h3>');
  result = result.replace(/^## (.+)$/gm, '<h2>$1</h2>');
  result = result.replace(/^# (.+)$/gm, '<h1>$1</h1>');
  // Horizontal rule
  result = result.replace(/^---+$/gm, '<hr />');
  // Bold
  result = result.replace(/\*\*(.+?)\*\*/g, '<strong>$1</strong>');
  // Bullet lists: collect consecutive - lines
  result = result.replace(/((?:^- .+\n?)+)/gm, (block) => {
    const items = block.trim().split('\n')
      .map((l) => `<li>${l.replace(/^- /, '').trim()}</li>`)
      .join('');
    return `<ul>${items}</ul>`;
  });
  // Numbered lists
  result = result.replace(/((?:^\d+\. .+\n?)+)/gm, (block) => {
    const items = block.trim().split('\n')
      .map((l) => `<li>${l.replace(/^\d+\. /, '').trim()}</li>`)
      .join('');
    return `<ol>${items}</ol>`;
  });
  // Paragraphs: wrap plain text separated by blank lines
  result = result.split(/\n{2,}/).map((para) => {
    const t = para.trim();
    if (!t) return '';
    if (/^<(h[123]|hr|ul|ol|table|p)/.test(t)) return t;
    return `<p>${t.replace(/\n/g, ' ')}</p>`;
  }).join('\n');

  return result;
}

export function CVEInvestigationSummary({
  visible,
  input,
  initialSummary = null,
  initialMode = 'deterministic',
  autoGenerate = true,
  readOnly = false,
}: Props) {
  const actor = useActor();
  const canUseAiSummary = canUseEntitlement(actor, 'ai.investigation_summary');
  const [deterministicSummary, setDeterministicSummary] = React.useState<InvestigationSummaryResponse | null>(null);
  const [aiSummary, setAiSummary] = React.useState<InvestigationSummaryResponse | null>(null);
  const [error, setError] = React.useState<string | null>(null);
  const [rawText, setRawText] = React.useState<string | null>(null);
  const [loading, setLoading] = React.useState(false);
  const [loadingIndex, setLoadingIndex] = React.useState(0);
  const [expandedExternalAssets, setExpandedExternalAssets] = React.useState(false);
  const [summaryMode, setSummaryMode] = React.useState<SummaryMode>(initialMode);
  const inputKey = React.useMemo(() => JSON.stringify(input), [input]);

  // Derived: whichever summary is currently displayed
  const summary = summaryMode === 'ai' ? aiSummary : deterministicSummary;

  const externalAssets = React.useMemo(
    () => input.affectedAssets.filter((asset) => asset.externalFacing),
    [input.affectedAssets]
  );

  const runGenerate = React.useCallback(async (mode: SummaryMode) => {
    if (mode !== 'deterministic') setLoading(true);
    setError(null);
    setRawText(null);
    setSummaryMode(mode);
    const result = await generateSummaryRequest(input, mode);
    if (mode === 'ai') {
      setAiSummary(result.summary ?? null);
    } else {
      setDeterministicSummary(result.summary ?? null);
    }
    setRawText(result.rawText ?? null);
    setError(result.error ?? null);
    setLoading(false);
    // Persist to mode-specific localStorage key
    if (result.summary) {
      const key = mode === 'ai' ? aiLocalKey(input.summary.cveId) : deterministicLocalKey(input.summary.cveId);
      try {
        window.localStorage.setItem(key, JSON.stringify({
          mode,
          generatedAt: result.summary.generatedAt ?? new Date().toISOString(),
          summary: result.summary,
        }));
      } catch { /* quota full — best effort */ }
    }
  }, [input]);

  // Load saved summary from localStorage for the given mode; returns true if found
  const loadFromLocalStorage = React.useCallback((mode: SummaryMode): boolean => {
    try {
      const key = mode === 'ai' ? aiLocalKey(input.summary.cveId) : deterministicLocalKey(input.summary.cveId);
      const raw = window.localStorage.getItem(key);
      if (raw) {
        const saved = JSON.parse(raw) as { mode: SummaryMode; summary: InvestigationSummaryResponse };
        if (mode === 'ai') {
          setAiSummary(saved.summary);
        } else {
          setDeterministicSummary(saved.summary);
        }
        setSummaryMode(mode);
        setError(null);
        setRawText(null);
        return true;
      }
    } catch { /* ignore */ }
    return false;
  }, [input.summary.cveId]);

  // Toggle to deterministic: show saved if available, otherwise generate
  const handleSummaryClick = React.useCallback(async () => {
    if (deterministicSummary) {
      setSummaryMode('deterministic');
      return;
    }
    if (loadFromLocalStorage('deterministic')) return;
    await runGenerate('deterministic');
  }, [deterministicSummary, loadFromLocalStorage, runGenerate]);

  // Toggle to AI: show saved if available, otherwise generate
  const handleAiSummaryClick = React.useCallback(async () => {
    if (aiSummary) {
      setSummaryMode('ai');
      return;
    }
    if (loadFromLocalStorage('ai')) return;
    await runGenerate('ai');
  }, [aiSummary, loadFromLocalStorage, runGenerate]);

  // Refresh: regenerate whichever mode is currently active
  const handleRefresh = React.useCallback(() => {
    void runGenerate(summaryMode);
  }, [summaryMode, runGenerate]);

  React.useEffect(() => {
    if (initialSummary) {
      if (initialMode === 'ai') {
        setAiSummary(initialSummary);
      } else {
        setDeterministicSummary(initialSummary);
      }
      setSummaryMode(initialMode);
    } else {
      // Restore from localStorage for both modes
      const detKey = deterministicLocalKey(input.summary.cveId);
      const aiKey = aiLocalKey(input.summary.cveId);
      try {
        const detRaw = window.localStorage.getItem(detKey);
        if (detRaw) {
          const saved = JSON.parse(detRaw) as { summary: InvestigationSummaryResponse };
          setDeterministicSummary(saved.summary);
        }
      } catch { /* ignore */ }
      try {
        const aiRaw = window.localStorage.getItem(aiKey);
        if (aiRaw) {
          const saved = JSON.parse(aiRaw) as { summary: InvestigationSummaryResponse };
          setAiSummary(saved.summary);
        }
      } catch { /* ignore */ }
      setSummaryMode(initialMode);
    }
    setError(null);
    setRawText(null);
  }, [initialSummary, initialMode, inputKey, input.summary.cveId]);

  // Only auto-generate when the panel first becomes visible — NOT on every inputKey change.
  React.useEffect(() => {
    if (!visible) return;
    if (!autoGenerate) return;
    // Don't auto-generate if a saved summary was already loaded from localStorage or props
    if (deterministicSummary || aiSummary) return;
    void runGenerate('deterministic');
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [visible, autoGenerate]);

  React.useEffect(() => {
    if (!loading) return;
    const id = window.setInterval(() => {
      setLoadingIndex((current) => (current + 1) % LOADING_STEPS.length);
    }, 1500);
    return () => window.clearInterval(id);
  }, [loading]);

  if (!visible) return null;

  return (
    <section style={{ display: 'grid', gap: 18 }}>
      <style>{`
        @keyframes investigationSummaryScan {
          0% { background-position: 0% 0; opacity: 0.55; }
          50% { background-position: 100% 0; opacity: 0.95; }
          100% { background-position: 0% 0; opacity: 0.55; }
        }
      `}</style>

      {loading ? (
        <div style={{
          background: COLORS.surface,
          border: `1px solid ${COLORS.border}`,
          borderRadius: 24,
          padding: 24,
          display: 'grid',
          gap: 16,
        }}>
          <div style={{ color: COLORS.accent, fontWeight: 700 }}>{LOADING_STEPS[loadingIndex]}</div>
          {Array.from({ length: 4 }).map((_, index) => (
            <div
              key={index}
              style={{
                height: index === 0 ? 92 : 120,
                borderRadius: 18,
                background: `linear-gradient(90deg, ${COLORS.surface}, ${tonedSurface(COLORS.accent, 22)}, ${COLORS.surface})`,
                backgroundSize: '200% 100%',
                animation: 'investigationSummaryScan 1.5s linear infinite',
                border: `1px solid ${COLORS.border}`,
              }}
            />
          ))}
        </div>
      ) : error ? (
        <div style={{
          background: COLORS.surface,
          border: `1px solid ${COLORS.danger}`,
          borderRadius: 24,
          padding: 24,
          display: 'grid',
          gap: 12,
        }}>
          <strong style={{ color: COLORS.text }}>Summary generation failed</strong>
          <div style={{ color: COLORS.muted }}>{error}</div>
          <div>
            <button type="button" className="btn btn-secondary btn-inline" onClick={() => void runGenerate(summaryMode)}>Retry</button>
          </div>
        </div>
      ) : rawText ? (
        <div style={{
          background: COLORS.surface,
          border: `1px solid ${COLORS.border}`,
          borderRadius: 24,
          padding: 24,
          display: 'grid',
          gap: 12,
        }}>
          <strong style={{ color: COLORS.text }}>Summary response</strong>
          <pre style={{
            margin: 0,
            padding: 16,
            background: COLORS.background,
            color: COLORS.title,
            borderRadius: 16,
            overflow: 'auto',
            maxHeight: 280,
          }}>{rawText}</pre>
        </div>
      ) : summary ? (
        <div style={{ display: 'grid', gap: 18 }}>
          <div style={{
            background: COLORS.surface,
            border: `1px solid ${COLORS.border}`,
            borderRadius: 24,
            padding: 24,
            display: 'flex',
            justifyContent: 'space-between',
            gap: 16,
            alignItems: 'center',
            flexWrap: 'wrap',
          }}>
            <div style={{ display: 'grid', gap: 10 }}>
              {/* Heading with bold-red refresh icon */}
              <div style={{ display: 'flex', alignItems: 'center', gap: 10 }}>
                <div style={{ fontFamily: 'ui-monospace, SFMono-Regular, Menlo, monospace', fontSize: 28, fontWeight: 800, color: COLORS.title }}>
                  CVE Investigation Summary — {input.summary.cveId}
                </div>
                {!readOnly && (
                  <button
                    type="button"
                    title={`Refresh ${summaryMode === 'ai' ? 'AI' : 'deterministic'} summary`}
                    onClick={handleRefresh}
                    style={{
                      background: 'none',
                      border: 'none',
                      cursor: 'pointer',
                      padding: '4px 6px',
                      fontSize: 22,
                      fontWeight: 900,
                      color: COLORS.danger,
                      lineHeight: 1,
                      display: 'flex',
                      alignItems: 'center',
                    }}
                  >
                    ↻
                  </button>
                )}
              </div>
              <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                <span style={pillStyle(severityColor(input.summary.severity), true)}>{input.summary.severity}</span>
                <span style={pillStyle(COLORS.text, false, { background: COLORS.background, borderColor: COLORS.border })}>
                  CVSS {input.summary.cvssScore ?? '—'}
                </span>
                {input.summary.inKev ? <span style={pillStyle(COLORS.warning, false)}>KEV</span> : null}
                <span
                  style={pillStyle(
                    summaryMode === 'ai' ? COLORS.accent : COLORS.text,
                    false,
                    summaryMode === 'ai'
                      ? undefined
                      : { background: COLORS.background, borderColor: COLORS.borderStrong }
                  )}
                >
                  {summaryMode === 'ai' ? 'AI Summary' : 'Deterministic Summary'}
                </span>
              </div>
            </div>
            <div style={{ display: 'flex', gap: 12, flexWrap: 'wrap' }}>
              {!readOnly ? (
                <>
                  <button
                    type="button"
                    className={summaryMode === 'deterministic' ? 'btn btn-primary btn-inline' : 'btn btn-secondary btn-inline'}
                    onClick={() => void handleSummaryClick()}
                  >
                    Summary
                  </button>
                  <button
                    type="button"
                    className={summaryMode === 'ai' ? 'btn btn-primary btn-inline' : 'btn btn-secondary btn-inline'}
                    disabled={!canUseAiSummary}
                    title="Show AI summary"
                    onClick={() => void handleAiSummaryClick()}
                  >
                    AI Summary
                  </button>
                </>
              ) : null}
              <button type="button" className="btn btn-secondary btn-inline" onClick={() => void exportWordDocument(input, summary, summaryMode)}>Export Word Doc</button>
            </div>
          </div>

          {summary.markdownReport ? (
            <div className="inv-summary-markdown-panel">
              <div
                className="inv-summary-markdown-body"
                dangerouslySetInnerHTML={{ __html: renderMarkdown(summary.markdownReport) }}
              />
            </div>
          ) : (
            <>
          <div style={{
            background: COLORS.surface,
            border: `1px solid ${COLORS.border}`,
            borderLeft: `4px solid ${COLORS.accent}`,
            borderRadius: 24,
            padding: 24,
            color: COLORS.text,
            lineHeight: 1.7,
          }}>
            <div style={sectionTitleStyle}>Executive Summary</div>
            <div style={{ color: COLORS.text }}>{summary.executiveSummary}</div>
          </div>

          <div style={{
            display: 'grid',
            gridTemplateColumns: '1.1fr 1.2fr 1fr',
            gap: 16,
          }}>
            <div style={cardStyle}>
              <div style={sectionTitleStyle}>Impact Analysis</div>
              <div style={{ display: 'grid', gap: 14 }}>
                <div style={{ fontSize: 14, color: COLORS.muted }}>Risk meter</div>
                <div style={{ height: 12, borderRadius: 999, background: COLORS.track, overflow: 'hidden' }}>
                  <div style={{ width: `${summary.riskAnalysis.score}%`, height: '100%', background: riskMeterGradient(summary.riskAnalysis.score) }} />
                </div>
                <div style={{ color: COLORS.title, fontSize: 32, fontWeight: 800 }}>{summary.riskAnalysis.level}</div>
                <div style={{ color: COLORS.muted, lineHeight: 1.7 }}>{summary.riskAnalysis.rationale}</div>
              </div>
            </div>

            <div style={cardStyle}>
              <div style={sectionTitleStyle}>Asset Exposure Breakdown</div>
              <div style={{ display: 'grid', gap: 14 }}>
                <div style={{ display: 'grid', gridTemplateColumns: '1fr 1fr', gap: 12 }}>
                  <div style={miniStatStyle}>
                    <div style={{ color: COLORS.accent }}>External</div>
                    <strong style={{ fontSize: 28, color: COLORS.text }}>{summary.impactAnalysis.externalFacingCount}</strong>
                  </div>
                  <div style={miniStatStyle}>
                    <div style={{ color: COLORS.muted }}>Internal</div>
                    <strong style={{ fontSize: 28, color: COLORS.text }}>{summary.impactAnalysis.internalAssetCount}</strong>
                  </div>
                </div>
                <button
                  type="button"
                  className="btn-link"
                  style={{ color: COLORS.accent, justifySelf: 'start' }}
                  onClick={() => setExpandedExternalAssets((current) => !current)}
                >
                  {expandedExternalAssets ? 'Hide' : 'Show'} external-facing assets
                </button>
                {expandedExternalAssets ? (
                  <div style={{ display: 'grid', gap: 10 }}>
                    {externalAssets.map((asset) => (
                      <div key={asset.id} style={{
                        border: `1px solid ${COLORS.border}`,
                        borderRadius: 16,
                        padding: 14,
                        background: COLORS.background,
                        display: 'grid',
                        gap: 6,
                      }}>
                        <strong style={{ color: COLORS.text }}>{asset.hostname}</strong>
                        <div style={{ color: COLORS.muted }}>{asset.owner || 'Unassigned'} · {asset.os || 'Unknown OS'}</div>
                        <div style={{ display: 'flex', gap: 8, flexWrap: 'wrap' }}>
                          <span style={pillStyle(COLORS.text, false, { background: COLORS.surfaceMuted, borderColor: COLORS.border })}>
                            {asset.environment || 'Unknown environment'}
                          </span>
                          <span style={pillStyle(COLORS.danger, false)}>External Facing</span>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : null}
              </div>
            </div>

            <div style={{ display: 'grid', gap: 12 }}>
              <div style={cardStyle}>
                <div style={sectionTitleStyle}>False Positive Summary</div>
                <div style={{ color: COLORS.text }}>{summary.impactAnalysis.falsePositiveSummary}</div>
              </div>
              <div style={cardStyle}>
                <div style={sectionTitleStyle}>EOL Risk</div>
                <div style={{ color: COLORS.text }}>{summary.impactAnalysis.eolRiskSummary}</div>
              </div>
              <div style={cardStyle}>
                <div style={sectionTitleStyle}>Patch Gap</div>
                <div style={{ color: COLORS.text }}>{summary.impactAnalysis.patchGapSummary}</div>
              </div>
            </div>
          </div>

          <div style={cardStyle}>
            <div style={sectionTitleStyle}>Remediation Plan</div>
            <div style={{ display: 'grid', gap: 12 }}>
              {summary.remediationPlan.map((action) => (
                <div key={action.priority} style={{
                  border: `1px solid ${COLORS.border}`,
                  borderRadius: 18,
                  padding: 18,
                  background: COLORS.background,
                  display: 'grid',
                  gap: 8,
                }}>
                  <div style={{ display: 'flex', gap: 10, alignItems: 'center', flexWrap: 'wrap' }}>
                    <span style={pillStyle(severityColor(action.priorityLabel === 'P1' ? 'CRITICAL' : action.priorityLabel === 'P2' ? 'HIGH' : 'MEDIUM'), false)}>{action.priorityLabel}</span>
                    <strong style={{ color: COLORS.text }}>{action.title}</strong>
                    <span style={{ ...pillStyle(timeframeColor(action.timeframe), false), marginLeft: 'auto' }}>{action.timeframe}</span>
                  </div>
                  <div style={{ color: COLORS.text }}>{action.detail}</div>
                  <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap' }}>
                    <span style={pillStyle(COLORS.text, false, { background: COLORS.surfaceMuted, borderColor: COLORS.border })}>{action.owner}</span>
                    <span style={pillStyle(COLORS.text, false, { background: COLORS.surfaceMuted, borderColor: COLORS.border })}>{action.type}</span>
                  </div>
                </div>
              ))}
            </div>
          </div>

          <div style={cardStyle}>
            <div style={sectionTitleStyle}>Key Findings</div>
            <ul style={{ margin: 0, paddingLeft: 20, color: COLORS.text, display: 'grid', gap: 8 }}>
              {summary.keyFindings.map((finding) => (
                <li key={finding} style={{ lineHeight: 1.7 }}>
                  <span style={{ color: COLORS.accent }}>{finding}</span>
                </li>
              ))}
            </ul>
          </div>

          {input.createdFindings?.length ? (
            <div style={cardStyle}>
              <div style={sectionTitleStyle}>Created Findings</div>
              <div style={{ display: 'grid', gap: 10 }}>
                {input.createdFindings.map((finding) => (
                  <div key={finding.displayId} style={{
                    border: `1px solid ${COLORS.border}`,
                    borderRadius: 16,
                    padding: 14,
                    background: COLORS.background,
                    display: 'grid',
                    gap: 6,
                  }}>
                    <div style={{ display: 'flex', gap: 10, flexWrap: 'wrap', alignItems: 'center' }}>
                      <strong style={{ color: COLORS.text }}>{finding.displayId}</strong>
                      <span style={pillStyle(COLORS.text, false, { background: COLORS.surfaceMuted, borderColor: COLORS.border })}>{finding.status}</span>
                      <span style={pillStyle(severityColor(finding.severity), false)}>{finding.severity}</span>
                    </div>
                    <div style={{ color: COLORS.text }}>
                      {finding.assetName} · {finding.packageName} {finding.packageVersion || '—'}
                    </div>
                    <div style={{ color: COLORS.muted, fontSize: 12 }}>
                      Decision: {finding.decisionState}
                      {finding.assignedTo ? ` · Assignee: ${finding.assignedTo}` : ''}
                      {finding.incidentId ? ` · Incident: ${finding.incidentId}` : ''}
                    </div>
                  </div>
                ))}
              </div>
            </div>
          ) : null}

          <div style={{
            display: 'grid',
            gridTemplateColumns: 'repeat(6, minmax(0, 1fr))',
            gap: 12,
          }}>
            {[
              ['Total Affected', summary.metrics.totalAffected],
              ['True Positives', summary.metrics.truePositives],
              ['False Positives', summary.metrics.falsePositives],
              ['External Facing', summary.metrics.externalFacing],
              ['Unpatched Vulnerable', summary.metrics.unpatchedVulnerable],
              ['EOL Count', summary.metrics.eolCount],
            ].map(([label, value]) => (
              <div key={label} style={miniStatStyle}>
                <div style={{ color: COLORS.muted, fontSize: 12 }}>{label}</div>
                <strong style={{ color: COLORS.text, fontSize: 26 }}>{value}</strong>
              </div>
            ))}
          </div>
            </>
          )}
        </div>
      ) : null}
    </section>
  );
}

function pillStyle(
  color: string,
  outline: boolean,
  options?: {
    background?: string;
    borderColor?: string;
  }
): React.CSSProperties {
  return {
    display: 'inline-flex',
    alignItems: 'center',
    padding: '6px 12px',
    borderRadius: 999,
    border: `1px solid ${options?.borderColor ?? (outline ? tonedBorder(color, 42) : tonedBorder(color))}`,
    background: options?.background ?? (outline ? 'transparent' : tonedSurface(color)),
    color,
    fontWeight: 700,
    fontSize: 13,
  };
}

const cardStyle: React.CSSProperties = {
  background: COLORS.surface,
  border: `1px solid ${COLORS.border}`,
  borderRadius: 24,
  padding: 24,
  display: 'grid',
  gap: 14,
};

const miniStatStyle: React.CSSProperties = {
  background: COLORS.surfaceMuted,
  border: `1px solid ${COLORS.border}`,
  borderRadius: 18,
  padding: 18,
  display: 'grid',
  gap: 8,
};

const sectionTitleStyle: React.CSSProperties = {
  color: COLORS.title,
  fontSize: 14,
  letterSpacing: '0.12em',
  textTransform: 'uppercase',
  fontWeight: 800,
};
