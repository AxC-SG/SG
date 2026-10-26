import type { InvestigationSummaryInput } from './CVEInvestigationSummary';

export const mockInvestigationSummaryInput: InvestigationSummaryInput = {
  summary: {
    cveId: 'CVE-2024-21413',
    title: 'Microsoft Outlook Remote Code Execution Vulnerability',
    description: 'A crafted email can trigger remote code execution when a vulnerable Outlook client processes an external reference.',
    severity: 'CRITICAL',
    cvssScore: 9.8,
    epssScore: 0.9299,
    inKev: true,
    exploitAvailable: true,
    patchAvailable: true,
    patchVersions: 'Office 2016 16.0.17328',
  },
  investigation: {
    leadAnalyst: 'Alex Martinez',
  },
  runbookResults: [
    { id: 'review-asset-inventory', title: 'Review Asset Inventory', state: 'DONE' },
    { id: 'find-false-positive', title: 'Find False Positive', state: 'DONE' },
    { id: 'end-of-life-analysis', title: 'End-of-Life Analysis', state: 'DONE' },
    { id: 'installed-patch-info', title: 'Installed Patch Info', state: 'READY' },
  ],
  affectedAssets: [
    {
      id: 'host-1',
      hostname: 'mail-gateway-01',
      ipAddress: '10.10.10.12',
      os: 'Windows',
      owner: 'Messaging',
      environment: 'DMZ',
      externalFacing: true,
      critical: true,
      matchedSoftware: [{ software: 'office_2016', version: '2016' }],
    },
    {
      id: 'host-2',
      hostname: 'finance-lt-204',
      ipAddress: '10.10.22.44',
      os: 'Windows',
      owner: 'Finance IT',
      environment: 'Internal',
      externalFacing: false,
      critical: true,
      matchedSoftware: [{ software: 'office_2016', version: '16.0.11901.20218' }],
    },
  ],
  falsePositiveRows: [
    {
      software: 'chrome',
      version: '90',
      falsePositive: true,
      assetsNotImpacted: 4,
      vendorGuidance: 'Vendor advisory states the affected code path is not present in this build.',
    },
  ],
  eolRows: [
    {
      software: 'office_2016',
      vendor: 'Microsoft',
      version: '2016',
      lifecycle: 'End of Life',
      endOfSupport: '2025-10-14',
      endOfLife: '2025-10-14',
      recommendedUpgrade: 'Microsoft 365 Apps',
    },
  ],
};
