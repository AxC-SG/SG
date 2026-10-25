import React from 'react';
import { useQuery } from '@tanstack/react-query';
import { apiRequest } from '../../api/client';

interface OsvCoverageResponse {
  ecosystemCounts: Record<string, number>;
  totalAdvisories: number;
  lastSyncedAt?: string;
}

const ecosystemIcons: Record<string, string> = {
  'npm': '📦',
  'Python': '🐍',
  'Go': '🐹',
  'Rust': '🦀',
  'RubyGems': '💎',
  'Maven': '☕',
  'NuGet': '.NET',
  'Packagist': '🐘',
  'Other': '📚',
};

export const OsvConnectorPage: React.FC<{ tenantId: string }> = ({ tenantId }) => {
  const { data: coverage, isLoading } = useQuery({
    queryKey: ['osv-coverage', tenantId],
    queryFn: async () => {
      return apiRequest<OsvCoverageResponse>(`/tenants/${encodeURIComponent(tenantId)}/osv/coverage`);
    },
  });

  const formatDate = (date?: string) => {
    if (!date) return 'Never';
    return new Date(date).toLocaleDateString();
  };

  return (
    <div className="osv-connector-page">
      <div className="osv-header">
        <h2>OSV - Open Source Vulnerabilities</h2>
        <p className="description">
          Unified vulnerability database aggregating advisories from multiple sources
        </p>
      </div>

      {/* Coverage Card */}
      <div className="card osv-coverage-card">
        <div className="card-header">
          <h3>Ecosystem Coverage</h3>
        </div>
        <div className="card-content">
          {isLoading ? (
            <div className="loading">Loading coverage data...</div>
          ) : coverage?.ecosystemCounts ? (
            <div className="ecosystem-grid">
              {Object.entries(coverage.ecosystemCounts).map(([ecosystem, count]) => (
                <div key={ecosystem} className="ecosystem-card">
                  <div className="ecosystem-icon">{ecosystemIcons[ecosystem] || '📋'}</div>
                  <div className="ecosystem-name">{ecosystem}</div>
                  <div className="advisory-count">{count} advisories</div>
                </div>
              ))}
            </div>
          ) : (
            <div className="empty-state">No ecosystem data available</div>
          )}
        </div>
      </div>

      {/* Status Card */}
      <div className="card osv-status-card">
        <div className="card-header">
          <h3>Sync Status</h3>
        </div>
        <div className="card-content">
          <div className="status-info">
            <div className="status-row">
              <span className="status-label">Last Sync:</span>
              <span className="status-value">{formatDate(coverage?.lastSyncedAt)}</span>
            </div>
            <div className="status-row">
              <span className="status-label">Total Advisories:</span>
              <span className="status-badge">{coverage?.totalAdvisories || 0}</span>
            </div>
            <div className="status-row">
              <span className="status-label">Ecosystem Support:</span>
              <span className="status-value">9 ecosystems</span>
            </div>
            <div className="status-row">
              <span className="status-label">Update Frequency:</span>
              <span className="status-value">Hourly (02:45 UTC)</span>
            </div>
          </div>
        </div>
      </div>

      {/* About Card */}
      <div className="card osv-about-card">
        <div className="card-header">
          <h3>About OSV</h3>
        </div>
        <div className="card-content">
          <p className="description">
            OSV is a unified vulnerability database that aggregates advisories from multiple authoritative sources:
          </p>
          <ul className="source-list">
            <li><strong>GitHub Security Advisories</strong> - GitHub-specific vulnerability data</li>
            <li><strong>National Vulnerability Database (NVD)</strong> - US government CVE database</li>
            <li><strong>PyPA</strong> - Python Package Authority advisories</li>
            <li><strong>RustSec</strong> - Rust security advisories</li>
            <li><strong>Go Vulndb</strong> - Go programming language vulnerabilities</li>
            <li><strong>RubySec</strong> - Ruby security advisories</li>
            <li><strong>And more...</strong> - Continuous expansion of supported ecosystems</li>
          </ul>
          <p className="note">
            OSV provides automatic deduplication across sources, ensuring you see each vulnerability once with all related references (CVE, GHSA, etc.).
          </p>
        </div>
      </div>

      {/* Integration Card */}
      <div className="card osv-integration-card">
        <div className="card-header">
          <h3>Integration Details</h3>
        </div>
        <div className="card-content">
          <div className="integration-info">
            <div className="integration-row">
              <span className="label">Status:</span>
              <span className="badge active">Active</span>
            </div>
            <div className="integration-row">
              <span className="label">Sync Schedule:</span>
              <span className="value">Daily at 02:45 UTC</span>
            </div>
            <div className="integration-row">
              <span className="label">Tenant Scope:</span>
              <span className="value">Platform-wide (shared cache)</span>
            </div>
            <div className="integration-row">
              <span className="label">Data Isolation:</span>
              <span className="value">Per-tenant correlation</span>
            </div>
            <div className="integration-row">
              <span className="label">Deduplication:</span>
              <span className="value">Automatic (CVE ↔ GHSA ↔ OSV)</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  );
};
