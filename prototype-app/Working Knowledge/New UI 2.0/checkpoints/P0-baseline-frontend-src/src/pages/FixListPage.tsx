import React, { useState } from 'react';

export function FixListPage() {
  const [searchTerm, setSearchTerm] = useState('');
  const [filterStatus, setFilterStatus] = useState('all');
  const [selectedFix, setSelectedFix] = useState<string | null>(null);

  const fixes = [
    {
      id: 'kb5039830',
      externalId: 'KB5039830',
      title: 'Windows Server 2022 Security Update',
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
      cveCount: 3,
      createdAt: '2024-09-10'
    },
    {
      id: 'kb5039329',
      externalId: 'KB5039329',
      title: 'Critical RCE Patch (CVE-2024-47001)',
      sourceSystem: 'SCCM',
      severity: 'Critical',
      ecosystem: 'Windows',
      packageName: 'Windows 11',
      fixedVersion: '24H2',
      fixType: 'PATCH',
      status: 'ACTIVE',
      applicableAssets: 1200,
      deployedAssets: 892,
      deploymentRate: 74.3,
      requiresReboot: true,
      estimatedDowntimeMinutes: 20,
      cveCount: 1,
      createdAt: '2024-09-15'
    },
    {
      id: 'rhsa-2026-001',
      externalId: 'RHSA-2026:001',
      title: 'Red Hat Linux Kernel Update',
      sourceSystem: 'BigFix',
      severity: 'High',
      ecosystem: 'Linux',
      packageName: 'kernel',
      fixedVersion: '6.1.5',
      fixType: 'PATCH',
      status: 'ACTIVE',
      applicableAssets: 890,
      deployedAssets: 634,
      deploymentRate: 71.2,
      requiresReboot: true,
      estimatedDowntimeMinutes: 10,
      cveCount: 2,
      createdAt: '2024-09-12'
    },
    {
      id: 'tnm-patch-001',
      externalId: 'TNM-PATCH-001',
      title: 'Tanium Endpoint Update',
      sourceSystem: 'Tanium',
      severity: 'Medium',
      ecosystem: 'Cross-platform',
      packageName: 'Tanium Client',
      fixedVersion: '8.2.5',
      fixType: 'PATCH',
      status: 'ACTIVE',
      applicableAssets: 2100,
      deployedAssets: 1950,
      deploymentRate: 92.9,
      requiresReboot: false,
      estimatedDowntimeMinutes: 0,
      cveCount: 0,
      createdAt: '2024-09-18'
    }
  ];

  const filteredFixes = fixes.filter(fix => {
    const matchesSearch = fix.title.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         fix.externalId.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesStatus = filterStatus === 'all' || fix.status === filterStatus;
    return matchesSearch && matchesStatus;
  });

  const getSeverityColor = (severity: string) => {
    switch(severity) {
      case 'Critical': return '#E63946';
      case 'High': return '#FF9800';
      case 'Medium': return '#FFC107';
      default: return '#4CAF50';
    }
  };

  return (
    <div className="page-grid">
      {/* Header */}
      <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border)' }}>
        <h1 style={{ margin: '0 0 8px 0' }}>Fixes & Patches</h1>
        <p style={{ margin: 0, color: 'var(--fg-muted)' }}>
          Browse and manage all available patches and fixes
        </p>
      </div>

      {/* Filters & Search */}
      <div className="panel" style={{ padding: 16, display: 'grid', gap: 12 }}>
        <div>
          <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
            Search Fixes
          </label>
          <input
            type="text"
            placeholder="Search by title or KB number..."
            value={searchTerm}
            onChange={(e) => setSearchTerm(e.target.value)}
            style={{
              width: '100%',
              padding: '8px 12px',
              border: '1px solid var(--border)',
              borderRadius: 4,
              fontSize: '0.875rem'
            }}
          />
        </div>

        <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
          <div>
            <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
              Status
            </label>
            <select
              value={filterStatus}
              onChange={(e) => setFilterStatus(e.target.value)}
              style={{
                width: '100%',
                padding: '8px 12px',
                border: '1px solid var(--border)',
                borderRadius: 4,
                fontSize: '0.875rem'
              }}
            >
              <option value="all">All Statuses</option>
              <option value="ACTIVE">Active</option>
              <option value="DEPRECATED">Deprecated</option>
              <option value="SUPERSEDED">Superseded</option>
            </select>
          </div>
        </div>
      </div>

      {/* Fixes Table */}
      <div className="panel" style={{ padding: 24, overflowX: 'auto' }}>
        <h3 style={{ margin: '0 0 16px 0' }}>Available Patches ({filteredFixes.length})</h3>
        <table style={{ width: '100%', fontSize: '0.875rem', borderCollapse: 'collapse' }}>
          <thead>
            <tr style={{ borderBottom: '2px solid var(--border)' }}>
              <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>KB/Patch ID</th>
              <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>Title</th>
              <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Severity</th>
              <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Source</th>
              <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Coverage</th>
              <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>CVEs</th>
              <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Action</th>
            </tr>
          </thead>
          <tbody>
            {filteredFixes.map((fix) => (
              <tr key={fix.id} style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '12px 0' }}>
                  <code style={{ background: 'var(--panel-muted)', padding: '2px 6px', borderRadius: 3, fontSize: '0.75rem' }}>
                    {fix.externalId}
                  </code>
                </td>
                <td style={{ padding: '12px 0', maxWidth: 300 }}>
                  <div style={{ fontWeight: 500 }}>{fix.title}</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 2 }}>
                    {fix.ecosystem} • {fix.packageName} v{fix.fixedVersion}
                  </div>
                </td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>
                  <span style={{
                    background: getSeverityColor(fix.severity),
                    color: 'white',
                    padding: '4px 8px',
                    borderRadius: 4,
                    fontSize: '0.75rem',
                    fontWeight: 600
                  }}>
                    {fix.severity}
                  </span>
                </td>
                <td style={{ textAlign: 'center', padding: '12px 0', fontSize: '0.75rem' }}>
                  {fix.sourceSystem}
                </td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>
                  <div style={{ fontWeight: 600 }}>{fix.deploymentRate}%</div>
                  <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)' }}>
                    {fix.deployedAssets}/{fix.applicableAssets}
                  </div>
                </td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>
                  <span style={{
                    background: 'var(--panel-muted)',
                    padding: '2px 6px',
                    borderRadius: 3,
                    fontSize: '0.75rem',
                    fontWeight: 600
                  }}>
                    {fix.cveCount}
                  </span>
                </td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>
                  <button
                    onClick={() => setSelectedFix(fix.id)}
                    style={{
                      background: 'var(--panel-muted)',
                      border: '1px solid var(--border)',
                      padding: '4px 8px',
                      borderRadius: 4,
                      cursor: 'pointer',
                      fontSize: '0.75rem',
                      fontWeight: 500
                    }}
                  >
                    View
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>

      {/* Fix Detail Panel */}
      {selectedFix && (
        <div className="panel" style={{ padding: 24, marginTop: 24, borderLeft: '4px solid #0052CC' }}>
          <div style={{ display: 'flex', justifyContent: 'space-between', alignItems: 'center', marginBottom: 16 }}>
            <h3 style={{ margin: 0 }}>Fix Details</h3>
            <button
              onClick={() => setSelectedFix(null)}
              style={{
                background: 'transparent',
                border: 'none',
                cursor: 'pointer',
                fontSize: '1.5rem',
                color: 'var(--fg-muted)'
              }}
            >
              ✕
            </button>
          </div>

          {(() => {
            const fix = fixes.find(f => f.id === selectedFix);
            if (!fix) return null;

            return (
              <div style={{ display: 'grid', gap: 20 }}>
                {/* Summary */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                      Patch ID
                    </div>
                    <div style={{ fontWeight: 600 }}>{fix.externalId}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                      Severity
                    </div>
                    <div style={{ color: getSeverityColor(fix.severity), fontWeight: 600 }}>{fix.severity}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                      Type
                    </div>
                    <div style={{ fontWeight: 600 }}>{fix.fixType}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                      Source
                    </div>
                    <div style={{ fontWeight: 600 }}>{fix.sourceSystem}</div>
                  </div>
                </div>

                {/* Title and Details */}
                <div>
                  <h4 style={{ margin: '0 0 8px 0' }}>{fix.title}</h4>
                  <p style={{ margin: 0, color: 'var(--fg-muted)', fontSize: '0.875rem', lineHeight: '1.6' }}>
                    {fix.ecosystem} patch for {fix.packageName} v{fix.fixedVersion}. Released on {fix.createdAt}.
                  </p>
                </div>

                {/* Deployment Status */}
                <div style={{ background: 'var(--panel-muted)', padding: 12, borderRadius: 4 }}>
                  <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8, fontWeight: 600 }}>
                    Deployment Status
                  </div>
                  <div style={{ display: 'grid', gap: 8 }}>
                    <div>
                      <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                        <span>Deployment Coverage</span>
                        <span style={{ fontWeight: 600 }}>{fix.deploymentRate}%</span>
                      </div>
                      <div style={{ background: 'var(--border)', borderRadius: 4, height: 8, overflow: 'hidden' }}>
                        <div
                          style={{
                            background: fix.deploymentRate > 80 ? '#4CAF50' : fix.deploymentRate > 50 ? '#FF9800' : '#E63946',
                            height: '100%',
                            width: `${fix.deploymentRate}%`,
                            transition: 'width 0.3s'
                          }}
                        />
                      </div>
                      <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', marginTop: 4 }}>
                        {fix.deployedAssets} of {fix.applicableAssets} assets
                      </div>
                    </div>
                  </div>
                </div>

                {/* Impact Info */}
                <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                      Requires Reboot
                    </div>
                    <div style={{ fontWeight: 600 }}>{fix.requiresReboot ? 'Yes' : 'No'}</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                      Estimated Downtime
                    </div>
                    <div style={{ fontWeight: 600 }}>{fix.estimatedDowntimeMinutes} minutes</div>
                  </div>
                  <div>
                    <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 4 }}>
                      Related CVEs
                    </div>
                    <div style={{ fontWeight: 600 }}>{fix.cveCount} CVE{fix.cveCount !== 1 ? 's' : ''}</div>
                  </div>
                </div>

                {/* Actions */}
                <div style={{ display: 'flex', gap: 12 }}>
                  <button
                    style={{
                      background: '#0052CC',
                      color: 'white',
                      border: 'none',
                      padding: '8px 16px',
                      borderRadius: 4,
                      cursor: 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: 500
                    }}
                  >
                    View Related CVEs
                  </button>
                  <button
                    style={{
                      background: 'var(--panel-muted)',
                      border: '1px solid var(--border)',
                      padding: '8px 16px',
                      borderRadius: 4,
                      cursor: 'pointer',
                      fontSize: '0.875rem',
                      fontWeight: 500
                    }}
                  >
                    View Deployment Details
                  </button>
                </div>
              </div>
            );
          })()}
        </div>
      )}
    </div>
  );
}
