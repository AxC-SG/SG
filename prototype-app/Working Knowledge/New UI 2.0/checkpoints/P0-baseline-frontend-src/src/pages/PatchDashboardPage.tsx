import React from 'react';

export function PatchDashboardPage() {
  return (
    <div className="page-grid">
      {/* Header */}
      <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border)' }}>
        <h1 style={{ margin: '0 0 8px 0' }}>Patch Management Dashboard</h1>
        <p style={{ margin: 0, color: 'var(--fg-muted)' }}>
          Monitor patch coverage, deployment status, and auto-resolution metrics across all endpoints
        </p>
      </div>

      {/* Key Metrics Row */}
      <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 16 }}>
        <div className="panel" style={{ padding: 20 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Patch Coverage
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 600, marginBottom: 8 }}>82%</div>
          <div style={{ fontSize: '0.875rem', color: '#4CAF50' }}>↑ 5% from last week</div>
        </div>

        <div className="panel" style={{ padding: 20 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Health Score
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 600, marginBottom: 8 }}>8.4/10</div>
          <div style={{ fontSize: '0.875rem', color: '#4CAF50' }}>Excellent patch posture</div>
        </div>

        <div className="panel" style={{ padding: 20 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Pending Patches
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 600, marginBottom: 8 }}>1,247</div>
          <div style={{ fontSize: '0.875rem', color: '#FF9800' }}>23 critical patches</div>
        </div>

        <div className="panel" style={{ padding: 20 }}>
          <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
            Auto-Resolved Findings
          </div>
          <div style={{ fontSize: '2.5rem', fontWeight: 600, marginBottom: 8 }}>342</div>
          <div style={{ fontSize: '0.875rem', color: '#4CAF50' }}>This month</div>
        </div>
      </div>

      {/* Coverage by Connector */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 16px 0' }}>Patch Coverage by Source</h3>
        <div style={{ display: 'grid', gap: 16 }}>
          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>SCCM/MECM</div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>1,523 patches (45%)</div>
            </div>
            <div style={{ background: 'var(--panel-muted)', borderRadius: 4, height: 8, overflow: 'hidden' }}>
              <div style={{ background: '#5B8FC4', height: '100%', width: '45%' }} />
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>BigFix</div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>1,089 patches (32%)</div>
            </div>
            <div style={{ background: 'var(--panel-muted)', borderRadius: 4, height: 8, overflow: 'hidden' }}>
              <div style={{ background: '#5B8FC4', height: '100%', width: '32%' }} />
            </div>
          </div>

          <div>
            <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 8 }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>Tanium</div>
              <div style={{ fontSize: '0.875rem', fontWeight: 600 }}>845 patches (23%)</div>
            </div>
            <div style={{ background: 'var(--panel-muted)', borderRadius: 4, height: 8, overflow: 'hidden' }}>
              <div style={{ background: '#E63946', height: '100%', width: '23%' }} />
            </div>
          </div>
        </div>
      </div>

      {/* Top Patches by Impact */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 16px 0' }}>Top Patches by CVE Impact</h3>
        <div style={{ overflowX: 'auto' }}>
          <table style={{ width: '100%', fontSize: '0.875rem', borderCollapse: 'collapse' }}>
            <thead>
              <tr style={{ borderBottom: '2px solid var(--border)' }}>
                <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>KB/Patch ID</th>
                <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>Title</th>
                <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>CVEs</th>
                <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Deployed</th>
                <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Status</th>
              </tr>
            </thead>
            <tbody>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '12px 0' }}>KB5039830</td>
                <td style={{ padding: '12px 0' }}>Windows Server 2022 Security Update</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>3</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>1,247 / 1,580 (79%)</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>
                  <span style={{ background: '#4CAF50', color: 'white', padding: '4px 8px', borderRadius: 4, fontSize: '0.75rem' }}>
                    In Progress
                  </span>
                </td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '12px 0' }}>KB5039329</td>
                <td style={{ padding: '12px 0' }}>Critical RCE Patch (CVE-2024-47001)</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>1</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>892 / 1,200 (74%)</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>
                  <span style={{ background: '#FF9800', color: 'white', padding: '4px 8px', borderRadius: 4, fontSize: '0.75rem' }}>
                    Pending
                  </span>
                </td>
              </tr>
              <tr style={{ borderBottom: '1px solid var(--border)' }}>
                <td style={{ padding: '12px 0' }}>RHSA-2026:001</td>
                <td style={{ padding: '12px 0' }}>Red Hat Linux Kernel Update</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>2</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>634 / 890 (71%)</td>
                <td style={{ textAlign: 'center', padding: '12px 0' }}>
                  <span style={{ background: '#4CAF50', color: 'white', padding: '4px 8px', borderRadius: 4, fontSize: '0.75rem' }}>
                    Deployed
                  </span>
                </td>
              </tr>
            </tbody>
          </table>
        </div>
      </div>

      {/* Deployment Timeline */}
      <div className="panel" style={{ padding: 24 }}>
        <h3 style={{ margin: '0 0 16px 0' }}>Recent Deployments</h3>
        <div style={{ display: 'grid', gap: 12 }}>
          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <div style={{ minWidth: 12, width: 12, height: 12, background: '#4CAF50', borderRadius: '50%' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>KB5039830 deployed to 127 endpoints</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)' }}>2 hours ago</div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <div style={{ minWidth: 12, width: 12, height: 12, background: '#FF9800', borderRadius: '50%' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>RHSA-2026:001 queued for 89 endpoints</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)' }}>4 hours ago</div>
            </div>
          </div>

          <div style={{ display: 'flex', gap: 12, alignItems: 'center' }}>
            <div style={{ minWidth: 12, width: 12, height: 12, background: '#4CAF50', borderRadius: '50%' }} />
            <div style={{ flex: 1 }}>
              <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>KB5039329 deployed to 892 endpoints</div>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)' }}>1 day ago</div>
            </div>
          </div>
        </div>
      </div>

      {/* Auto-Resolution Recommendations */}
      <div className="panel" style={{ padding: 24, background: 'var(--info-bg)', border: '1px solid var(--info-border)' }}>
        <h4 style={{ margin: '0 0 12px 0', color: 'var(--info)' }}>✓ Fix Intelligence Recommendations</h4>
        <div style={{ display: 'grid', gap: 8, fontSize: '0.875rem', color: 'var(--info)' }}>
          <div>• 342 findings auto-resolved this month via patch deployment tracking</div>
          <div>• 23 critical CVEs have deployment coverage &gt;80%, eligible for auto-resolution</div>
          <div>• SCCM is your primary patch source (45% of all patches) — prioritize KB5039830</div>
          <div>• Next auto-sync: 6 hours from now</div>
        </div>
      </div>
    </div>
  );
}
