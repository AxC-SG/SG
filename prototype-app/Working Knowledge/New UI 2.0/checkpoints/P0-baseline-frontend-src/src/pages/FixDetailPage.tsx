import React, { useState, useEffect } from 'react';
import { useParams, useNavigate } from 'react-router-dom';

interface FixResponse {
  id: string;
  externalId: string;
  title: string;
  description: string;
  severity: string;
  ecosystem: string;
  sourceSystem: string;
  packageName: string;
  fixedVersion: string;
  fixType: string;
  status: string;
  applicableAssets: number;
  deployedAssets: number;
  deploymentRate: number;
  requiresReboot: boolean;
  estimatedDowntimeMinutes: number;
  installationInstructions: string;
  knownLimitations: string;
  patchUrl: string;
  createdAt: string;
  updatedAt: string;
  syncedAt: string;
  relatedCves?: Array<{ id: string; title: string; severity: string }>;
  deploymentStatus?: Array<{ status: string; count: number; percentage: number }>;
  affectedSoftware?: Array<{ name: string; version: string; assetCount: number }>;
  sourceMetadata?: Record<string, unknown>;
}

export function FixDetailPage() {
  const { fixId } = useParams<{ fixId: string }>();
  const navigate = useNavigate();
  const [fix, setFix] = useState<FixResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!fixId) {
      setError('Fix ID not provided');
      setLoading(false);
      return;
    }

    const fetchFix = async () => {
      try {
        setLoading(true);
        setError(null);

        const apiBase = import.meta.env.VITE_API_BASE || 'http://localhost:8080/api';
        const headers: Record<string, string> = {};
        if (import.meta.env.DEV) {
          headers['X-API-Key'] = import.meta.env.VITE_API_KEY || 'change-me-in-prod';
          headers['X-Creator-Key'] = import.meta.env.VITE_CREATOR_KEY || 'local-creator';
        }

        const response = await fetch(`${apiBase}/fix-intelligence/fixes/${fixId}`, { headers });

        if (!response.ok) throw new Error(`Failed to fetch fix: ${response.statusText}`);

        const data = await response.json();
        setFix(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Unknown error');
        console.error('Error fetching fix:', err);
      } finally {
        setLoading(false);
      }
    };

    fetchFix();
  }, [fixId]);

  if (loading) {
    return (
      <div className="page-grid">
        <div style={{ padding: '40px', textAlign: 'center', color: 'var(--fg-muted)' }}>
          Loading fix details...
        </div>
      </div>
    );
  }

  if (error || !fix) {
    return (
      <div className="page-grid">
        <div style={{ padding: '40px', textAlign: 'center' }}>
          <div style={{ color: '#E63946', marginBottom: '12px' }}>
            ⚠️ Error: {error || 'Fix not found'}
          </div>
          <button
            onClick={() => navigate('/fix-intelligence/all')}
            style={{
              background: '#0052CC',
              color: 'white',
              border: 'none',
              padding: '8px 16px',
              borderRadius: 4,
              cursor: 'pointer'
            }}
          >
            ← Back to Fix Intelligence
          </button>
        </div>
      </div>
    );
  }

  const defaultFix = {
    id: 'kb5039830',
    externalId: 'KB5039830',
    title: 'Windows Server 2022 Security Update',
    description: 'Critical security update for Windows Server 2022 addressing multiple vulnerabilities including remote code execution and privilege escalation issues.',
    sourceSystem: 'SCCM',
    severity: 'Critical',
    ecosystem: 'Windows',
    packageName: 'Windows Server 2022',
    fixedVersion: '21H2',
    fixType: 'PATCH',
    status: 'ACTIVE',
    applicableAssets: 1580,
    deployedAssets: 1247,
    deploymentRate: 78.9,
    requiresReboot: true,
    estimatedDowntimeMinutes: 15,
    installationInstructions: 'Download the patch from Microsoft Update Catalog or Windows Update. Run the installer and follow the on-screen instructions. System reboot required.',
    knownLimitations: 'Incompatible with certain third-party antivirus software versions older than 2024.1. Test in staging environment first.',
    patchUrl: 'https://www.catalog.update.microsoft.com/Search.aspx?q=KB5039830',
    createdAt: '2024-09-10',
    updatedAt: '2024-09-20',
    syncedAt: '2024-09-24T14:30:00Z',
    relatedCves: [
      { id: 'CVE-2024-47001', title: 'RCE Vulnerability', severity: 'Critical' },
      { id: 'CVE-2024-47002', title: 'Privilege Escalation', severity: 'High' },
      { id: 'CVE-2024-47003', title: 'Information Disclosure', severity: 'Medium' }
    ],
    deploymentStatus: [
      { status: 'DEPLOYED', count: 1247, percentage: 78.9 },
      { status: 'PENDING', count: 245, percentage: 15.5 },
      { status: 'FAILED', count: 88, percentage: 5.6 }
    ],
    affectedSoftware: [
      { name: 'Windows Server 2022', version: '21H2', assetCount: 1580 }
    ],
    sourceMetadata: {
      releaseDate: '2024-09-10',
      classifications: ['Security Update', 'Critical'],
      supportUrl: 'https://support.microsoft.com/en-us/help/5039830'
    }
  };

  const displayFix = fix || defaultFix;

  return (
    <div className="page-grid">
      {/* Header */}
      <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border)' }}>
        <button
          onClick={() => navigate('/fix-intelligence/all')}
          style={{
            background: 'transparent',
            border: 'none',
            color: '#0052CC',
            cursor: 'pointer',
            fontSize: '0.875rem',
            marginBottom: '12px',
            padding: 0
          }}
        >
          ← Back to Fix Intelligence
        </button>
        <div style={{ display: 'flex', alignItems: 'center', gap: 12, marginBottom: 8 }}>
          <span style={{
            background: displayFix.severity === 'Critical' ? '#E63946' : displayFix.severity === 'High' ? '#FF9800' : displayFix.severity === 'Medium' ? '#FFC107' : '#4CAF50',
            color: 'white',
            padding: '4px 8px',
            borderRadius: 4,
            fontSize: '0.75rem',
            fontWeight: 600
          }}>
            {displayFix.severity}
          </span>
          <h1 style={{ margin: 0 }}>{displayFix.title}</h1>
        </div>
        <p style={{ margin: 0, color: 'var(--fg-muted)' }}>
          Patch ID: <code style={{ background: 'var(--panel-muted)', padding: '2px 6px', borderRadius: 3 }}>
            {displayFix.externalId}
          </code>
        </p>
      </div>

      {/* Key Metrics */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
        <div className="panel" style={{ padding: 16 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Coverage
          </div>
          <div style={{ fontSize: '2rem', fontWeight: 600, marginBottom: 4 }}>{displayFix.deploymentRate}%</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)' }}>
            {displayFix.deployedAssets}/{displayFix.applicableAssets} deployed
          </div>
        </div>

        <div className="panel" style={{ padding: 16 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Ecosystem
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 600 }}>{displayFix.ecosystem}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
            {displayFix.packageName}
          </div>
        </div>

        <div className="panel" style={{ padding: 16 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Impact
          </div>
          <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>
            Reboot: {displayFix.requiresReboot ? 'Yes' : 'No'}
          </div>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
            {displayFix.estimatedDowntimeMinutes} min downtime
          </div>
        </div>

        <div className="panel" style={{ padding: 16 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Source
          </div>
          <div style={{ fontSize: '1.1rem', fontWeight: 600 }}>{displayFix.sourceSystem}</div>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
            Last synced: {new Date(displayFix.syncedAt).toLocaleDateString()}
          </div>
        </div>
      </div>

      {/* Description */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 12px 0' }}>Overview</h3>
        <p style={{ margin: 0, color: 'var(--fg-muted)', lineHeight: '1.6' }}>
          {displayFix.description}
        </p>
      </div>

      {/* Deployment Status */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 16px 0' }}>Deployment Status</h3>

        {/* Overall Progress */}
        <div style={{ marginBottom: 20 }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
            <span style={{ fontWeight: 500 }}>Overall Deployment</span>
            <span style={{ fontWeight: 600 }}>{displayFix.deploymentRate}%</span>
          </div>
          <div style={{ background: 'var(--panel-muted)', borderRadius: 4, height: 12, overflow: 'hidden' }}>
            <div
              style={{
                background: '#4CAF50',
                height: '100%',
                width: `${displayFix.deploymentRate}%`,
                transition: 'width 0.3s'
              }}
            />
          </div>
        </div>

        {/* Status Breakdown */}
        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
          {displayFix.deploymentStatus && displayFix.deploymentStatus.map((status, idx) => (
            <div key={idx} style={{ background: 'var(--panel-muted)', padding: 12, borderRadius: 4 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 6 }}>
                {status.status}
              </div>
              <div style={{ fontSize: '1.5rem', fontWeight: 600 }}>
                {status.count}
                <span style={{ fontSize: '0.875rem', color: 'var(--fg-muted)', marginLeft: 4 }}>
                  ({status.percentage}%)
                </span>
              </div>
            </div>
          ))}
        </div>
      </div>

      {/* Related CVEs */}
      {displayFix.relatedCves && displayFix.relatedCves.length > 0 && (
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 16px 0' }}>Related CVEs ({displayFix.relatedCves.length})</h3>
        <div style={{ display: 'grid', gap: 12 }}>
          {displayFix.relatedCves.map((cve, idx) => (
            <div key={idx} style={{ display: 'flex', alignItems: 'center', gap: 12, padding: 12, background: 'var(--panel-muted)', borderRadius: 4 }}>
              <span style={{
                background: cve.severity === 'Critical' ? '#E63946' : cve.severity === 'High' ? '#FF9800' : '#FFC107',
                color: 'white',
                padding: '2px 6px',
                borderRadius: 3,
                fontSize: '0.75rem',
                fontWeight: 600
              }}>
                {cve.severity}
              </span>
              <div style={{ flex: 1 }}>
                <div style={{ fontWeight: 500 }}>{cve.id}</div>
                <div style={{ fontSize: '0.875rem', color: 'var(--fg-muted)' }}>{cve.title}</div>
              </div>
              <button
                style={{
                  background: 'transparent',
                  border: '1px solid var(--border)',
                  padding: '4px 8px',
                  borderRadius: 4,
                  cursor: 'pointer',
                  fontSize: '0.75rem'
                }}
              >
                View
              </button>
            </div>
          ))}
        </div>
      </div>
      )}

      {/* Installation Instructions */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 12px 0' }}>Installation Instructions</h3>
        <p style={{ margin: 0, color: 'var(--fg-muted)', lineHeight: '1.6', whiteSpace: 'pre-wrap' }}>
          {displayFix.installationInstructions}
        </p>
        <a href={displayFix.patchUrl} target="_blank" rel="noopener noreferrer"
           style={{ display: 'inline-block', marginTop: 12, color: '#0052CC', textDecoration: 'none' }}>
          → View on Microsoft Catalog
        </a>
      </div>

      {/* Known Limitations */}
      {displayFix.knownLimitations && (
        <div className="panel" style={{ padding: 24, borderLeft: '4px solid #FF9800', background: 'rgba(255, 152, 0, 0.05)' }}>
          <h3 style={{ margin: '0 0 12px 0', color: '#FF9800' }}>⚠ Known Limitations</h3>
          <p style={{ margin: 0, color: 'var(--fg-muted)', lineHeight: '1.6' }}>
            {displayFix.knownLimitations}
          </p>
        </div>
      )}

      {/* Affected Software */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 16px 0' }}>Affected Software</h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '0.875rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>Software</th>
                <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>Version</th>
                <th style={{ textAlign: 'right', padding: '12px 0', fontWeight: 600 }}>Assets</th>
              </tr>
            </thead>
            <tbody>
              {displayFix.affectedSoftware && displayFix.affectedSoftware.map((software, idx) => (
                <tr key={idx} style={{ borderBottom: '1px solid var(--border)' }}>
                  <td style={{ padding: '12px 0' }}>{software.name}</td>
                  <td style={{ padding: '12px 0' }}>{software.version}</td>
                  <td style={{ textAlign: 'right', padding: '12px 0', fontWeight: 600 }}>{software.assetCount}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      </div>

      {/* Actions */}
      <div style={{ display: 'flex', gap: 12, paddingTop: 12 }}>
        <button
          style={{
            background: '#0052CC',
            color: 'white',
            border: 'none',
            padding: '10px 20px',
            borderRadius: 4,
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 500
          }}
        >
          Deploy Patch
        </button>
        <button
          style={{
            background: 'var(--panel-muted)',
            border: '1px solid var(--border)',
            padding: '10px 20px',
            borderRadius: 4,
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 500
          }}
        >
          Schedule Deployment
        </button>
        <button
          style={{
            background: 'var(--panel-muted)',
            border: '1px solid var(--border)',
            padding: '10px 20px',
            borderRadius: 4,
            cursor: 'pointer',
            fontSize: '0.875rem',
            fontWeight: 500
          }}
        >
          View Deployment History
        </button>
      </div>
    </div>
  );
}
