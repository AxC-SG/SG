import React, { useState, useEffect, useCallback } from 'react';
import { useNavigate } from 'react-router-dom';
import type { FixIntelligenceRouteView } from '../app/routes';

interface Fix {
  id: string;
  externalId: string;
  title: string;
  fixType: string;
  severity: string;
  ecosystem: string;
  sourceSystem: string;
  packageName: string;
  fixedVersion: string;
  applicableAssets: number;
  deployedAssets: number;
  deploymentRate: number;
  requiresReboot: boolean;
  estimatedDowntimeMinutes: number;
  status: string;
}

interface Statistics {
  totalFixes: number;
  byType: Record<string, number>;
  bySeverity: Record<string, number>;
  byEcosystem: Record<string, number>;
  bySource?: Record<string, number>;
}

interface FixIntelligencePageProps {
  selectedView?: FixIntelligenceRouteView;
}

export function FixIntelligencePage({ selectedView = 'all' }: FixIntelligencePageProps) {
  const navigate = useNavigate();

  const getInitialView = useCallback(() => {
    if (selectedView === 'patches') return 'patches';
    if (selectedView === 'workarounds') return 'workarounds';
    if (selectedView === 'compensating-controls') return 'compensating-controls';
    return 'all';
  }, [selectedView]);

  const [activeView, setActiveView] = useState<FixIntelligenceRouteView>(getInitialView() as FixIntelligenceRouteView);
  const [searchTerm, setSearchTerm] = useState('');
  const [filterSeverity, setFilterSeverity] = useState('all');
  const [filterEcosystem, setFilterEcosystem] = useState('all');
  const [fixes, setFixes] = useState<Fix[]>([]);
  const [statistics, setStatistics] = useState<Statistics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    setActiveView(getInitialView() as FixIntelligenceRouteView);
  }, [getInitialView]);

  const fetchFixesAndStatistics = useCallback(async () => {
    try {
      setLoading(true);
      setError(null);

      const apiBase = import.meta.env.VITE_API_BASE || 'http://localhost:8080/api';

      let endpoint = '/fix-intelligence/fixes?page=0&size=100';

      if (activeView === 'patches') {
        endpoint = '/fix-intelligence/fixes-by-type/PATCH?page=0&size=100';
      } else if (activeView === 'workarounds') {
        endpoint = '/fix-intelligence/fixes-by-type/WORKAROUND?page=0&size=100';
      } else if (activeView === 'compensating-controls') {
        endpoint = '/fix-intelligence/fixes-by-type/COMPENSATING_CONTROL?page=0&size=100';
      }

      if (searchTerm) endpoint += `&search=${encodeURIComponent(searchTerm)}`;
      if (filterSeverity !== 'all') endpoint += `&severity=${filterSeverity}`;
      if (filterEcosystem !== 'all') endpoint += `&ecosystem=${filterEcosystem}`;

      const headers: Record<string, string> = {};
      if (import.meta.env.DEV) {
        headers['X-API-Key'] = import.meta.env.VITE_API_KEY || 'change-me-in-prod';
        headers['X-Creator-Key'] = import.meta.env.VITE_CREATOR_KEY || 'local-creator';
      }

      const [fixesRes, statsRes] = await Promise.all([
        fetch(`${apiBase}${endpoint}`, { headers }),
        fetch(`${apiBase}/fix-intelligence/statistics`, { headers })
      ]);

      if (!fixesRes.ok) throw new Error(`Failed to fetch fixes: ${fixesRes.statusText}`);
      if (!statsRes.ok) throw new Error(`Failed to fetch statistics: ${statsRes.statusText}`);

      const fixesData = await fixesRes.json();
      const statsData = await statsRes.json();

      setFixes(fixesData.content || []);
      setStatistics(statsData);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Unknown error');
      console.error('Error fetching fix intelligence:', err);
    } finally {
      setLoading(false);
    }
  }, [activeView, searchTerm, filterSeverity, filterEcosystem]);

  useEffect(() => {
    fetchFixesAndStatistics();
  }, [fetchFixesAndStatistics]);

  const defaultStatistics = {
    totalFixes: 100,
    byType: {
      PATCH: 85,
      WORKAROUND: 10,
      COMPENSATING_CONTROL: 5
    },
    bySeverity: {
      Critical: 15,
      High: 28,
      Medium: 42,
      Low: 15
    },
    byEcosystem: {
      Windows: 40,
      Linux: 30,
      macOS: 15,
      'Cross-platform': 15
    }
  };

  const displayStats = statistics ? {
    totalFixes: statistics.totalFixes,
    byType: statistics.byType,
    bySeverity: statistics.bySeverity,
    byEcosystem: statistics.byEcosystem
  } : defaultStatistics;

  const handleRowClick = (fixId: string) => {
    navigate(`/fix-intelligence/details/${fixId}`);
  };

  return (
    <div className="page-grid">
      {/* Header */}
      <div style={{ paddingBottom: 20, borderBottom: '1px solid var(--border)' }}>
        <h1 style={{ margin: '0 0 8px 0' }}>
          {activeView === 'all' && 'All Fixes'}
          {activeView === 'patches' && 'Patches'}
          {activeView === 'workarounds' && 'Workarounds'}
          {activeView === 'compensating-controls' && 'Compensating Controls'}
        </h1>
        <p style={{ margin: 0, color: 'var(--fg-muted)' }}>
          Comprehensive patch management and remediation solutions
        </p>
      </div>

      {/* Main Content Area */}
      <>
        {/* Statistics Cards */}
          <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(150px, 1fr))', gap: 12 }}>
            <div className="panel" style={{ padding: 16 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                Total Fixes
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 600 }}>{displayStats.totalFixes}</div>
            </div>

            <div className="panel" style={{ padding: 16 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                Critical Severity
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 600, color: '#E63946' }}>
                {displayStats.bySeverity?.Critical || 0}
              </div>
            </div>

            <div className="panel" style={{ padding: 16 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                High Priority
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 600, color: '#FF9800' }}>
                {displayStats.bySeverity?.High || 0}
              </div>
            </div>

            <div className="panel" style={{ padding: 16 }}>
              <div style={{ fontSize: '0.75rem', color: 'var(--fg-muted)', textTransform: 'uppercase', marginBottom: 8 }}>
                Ecosystems Covered
              </div>
              <div style={{ fontSize: '2rem', fontWeight: 600, color: '#4CAF50' }}>
                {displayStats.byEcosystem ? Object.keys(displayStats.byEcosystem).length : 0}
              </div>
            </div>
          </div>

          {/* Filters */}
          <div className="panel" style={{ padding: 16, display: 'grid', gap: 12 }}>
            <div>
              <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                Search Fixes
              </label>
              <input
                type="text"
                placeholder="Search by title, KB number, or ID..."
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

            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(200px, 1fr))', gap: 12 }}>
              <div>
                <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                  Severity
                </label>
                <select
                  value={filterSeverity}
                  onChange={(e) => setFilterSeverity(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    fontSize: '0.875rem'
                  }}
                >
                  <option value="all">All Severities</option>
                  <option value="Critical">Critical</option>
                  <option value="High">High</option>
                  <option value="Medium">Medium</option>
                  <option value="Low">Low</option>
                </select>
              </div>

              <div>
                <label style={{ display: 'block', fontSize: '0.875rem', fontWeight: 500, marginBottom: 6 }}>
                  Ecosystem
                </label>
                <select
                  value={filterEcosystem}
                  onChange={(e) => setFilterEcosystem(e.target.value)}
                  style={{
                    width: '100%',
                    padding: '8px 12px',
                    border: '1px solid var(--border)',
                    borderRadius: 4,
                    fontSize: '0.875rem'
                  }}
                >
                  <option value="all">All Ecosystems</option>
                  <option value="Windows">Windows</option>
                  <option value="Linux">Linux</option>
                  <option value="macOS">macOS</option>
                  <option value="Cross-platform">Cross-platform</option>
                </select>
              </div>
            </div>
          </div>

          {/* Severity Distribution */}
          <div className="panel" style={{ padding: 24 }}>
            <h3 style={{ margin: '0 0 16px 0' }}>Severity Distribution</h3>
            <div style={{ display: 'grid', gap: 12 }}>
              {displayStats.bySeverity && Object.entries(displayStats.bySeverity).map(([severity, count]: [string, number]) => {
                const total = displayStats.totalFixes;
                const percentage = (count * 100) / total;
                const colors: Record<string, string> = {
                  Critical: '#E63946',
                  High: '#FF9800',
                  Medium: '#FFC107',
                  Low: '#4CAF50'
                };

                return (
                  <div key={severity}>
                    <div style={{ display: 'flex', justifyContent: 'space-between', marginBottom: 6 }}>
                      <span style={{ fontWeight: 500 }}>{severity}</span>
                      <span style={{ fontWeight: 600 }}>{count} ({percentage.toFixed(1)}%)</span>
                    </div>
                    <div style={{ background: 'var(--panel-muted)', borderRadius: 4, height: 8, overflow: 'hidden' }}>
                      <div
                        style={{
                          background: colors[severity],
                          height: '100%',
                          width: `${percentage}%`,
                          transition: 'width 0.3s'
                        }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </div>

          {/* Ecosystem Coverage */}
          <div className="panel" style={{ padding: 24 }}>
            <h3 style={{ margin: '0 0 16px 0' }}>Ecosystem Coverage</h3>
            <div style={{ display: 'grid', gridTemplateColumns: 'repeat(auto-fit, minmax(120px, 1fr))', gap: 12 }}>
              {displayStats.byEcosystem && Object.entries(displayStats.byEcosystem).map(([ecosystem, count]: [string, number]) => (
                <div key={ecosystem} style={{ background: 'var(--panel-muted)', padding: 12, borderRadius: 4, textAlign: 'center' }}>
                  <div style={{ fontSize: '1.5rem', fontWeight: 600, marginBottom: 4 }}>{count}</div>
                  <div style={{ fontSize: '0.875rem', fontWeight: 500 }}>{ecosystem}</div>
                </div>
              ))}
            </div>
          </div>

        {/* Table View (Patches, Workarounds, Controls) */}
        {(activeView === 'patches' || activeView === 'workarounds' || activeView === 'compensating-controls') && (
        <div className="panel" style={{ padding: 24 }}>
          <div style={{ marginBottom: 16 }}>
            <input
              type="text"
              placeholder="Search by title or ID..."
              value={searchTerm}
              onChange={(e) => setSearchTerm(e.target.value)}
              style={{
                width: '100%',
                maxWidth: 400,
                padding: '8px 12px',
                border: '1px solid var(--border)',
                borderRadius: 4,
                fontSize: '0.875rem'
              }}
            />
          </div>

          {error && (
            <div style={{ background: '#FEE', padding: '12px', borderRadius: 4, marginBottom: 16, color: '#C33' }}>
              ⚠️ Error: {error}
            </div>
          )}

          {loading ? (
            <div style={{ padding: '40px', textAlign: 'center', color: 'var(--fg-muted)' }}>
              Loading {activeView === 'patches' ? 'patches' : activeView === 'workarounds' ? 'workarounds' : 'compensating-controls'}...
            </div>
          ) : (
            <div style={{ overflowX: 'auto' }}>
              <table style={{ width: '100%', fontSize: '0.875rem', borderCollapse: 'collapse' }}>
                <thead>
                  <tr style={{ borderBottom: '2px solid var(--border)' }}>
                    <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>ID</th>
                    <th style={{ textAlign: 'left', padding: '12px 0', fontWeight: 600 }}>Title</th>
                    <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Severity</th>
                    <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Ecosystem</th>
                    <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Source</th>
                    <th style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>Coverage</th>
                  </tr>
                </thead>
                <tbody>
                  {fixes.length > 0 ? (
                    fixes.map((fix, idx) => (
                      <tr
                        key={idx}
                        onClick={() => handleRowClick(fix.externalId)}
                        style={{
                          borderBottom: '1px solid var(--border)',
                          cursor: 'pointer',
                          background: 'transparent',
                          transition: 'background 0.2s'
                        }}
                        onMouseEnter={(e) => (e.currentTarget.style.background = 'var(--panel-muted)')}
                        onMouseLeave={(e) => (e.currentTarget.style.background = 'transparent')}
                      >
                        <td style={{ padding: '12px 0' }}>
                          <code style={{ background: 'var(--panel-muted)', padding: '2px 6px', borderRadius: 3, fontSize: '0.75rem' }}>
                            {fix.externalId}
                          </code>
                        </td>
                        <td style={{ padding: '12px 0' }}>
                          <div style={{ fontWeight: 500, maxWidth: 300 }}>{fix.title}</div>
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px 0' }}>
                          <span style={{
                            background: fix.severity === 'Critical' ? '#E63946' : fix.severity === 'High' ? '#FF9800' : fix.severity === 'Medium' ? '#FFC107' : '#4CAF50',
                            color: 'white',
                            padding: '4px 8px',
                            borderRadius: 4,
                            fontSize: '0.75rem',
                            fontWeight: 600
                          }}>
                            {fix.severity}
                          </span>
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px 0', fontSize: '0.875rem' }}>
                          {fix.ecosystem}
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px 0', fontSize: '0.875rem' }}>
                          {fix.sourceSystem}
                        </td>
                        <td style={{ textAlign: 'center', padding: '12px 0', fontWeight: 600 }}>
                          {fix.deploymentRate ? fix.deploymentRate.toFixed(0) + '%' : 'N/A'}
                        </td>
                      </tr>
                    ))
                  ) : (
                    <tr>
                      <td colSpan={6} style={{ textAlign: 'center', padding: '20px', color: 'var(--fg-muted)' }}>
                        No {activeView === 'patches' ? 'patches' : activeView === 'workarounds' ? 'workarounds' : 'compensating-controls'} found
                      </td>
                    </tr>
                  )}
                </tbody>
              </table>
            </div>
          )}
        </div>
        )}
      </>
    </div>
  );
}
