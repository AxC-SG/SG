# Week 3: Frontend Dashboard Implementation

**Timeline:** Oct 14 - Oct 18, 2026  
**Owner:** Frontend Engineer  
**Goal:** Patch dashboard fully functional, responsive, and integrated

---

## Overview: Dashboard Architecture

### Data Flow
```
Backend API (/api/patches/dashboard/*)
    ↓
React Hooks (useQuery)
    ↓
Component State
    ↓
UI Rendering (Patch Dashboard, Drill-Down, Config)
    ↓
Browser Display
```

### Pages to Build
1. **Patch Dashboard** (`/patches/dashboard`) — Overview + metrics
2. **Patch Drill-Down** (`/patches/{fixId}/deployment-status`) — Per-asset status
3. **Connector Configuration** (`/connect/patches`) — Setup UI
4. **Finding Integration** (Finding Detail Page) — Link patches to findings

---

## Day 11-12: Patch Dashboard Page

### Task 1.1: API Data Structure Understanding

**Backend Response Structure** (from PatchDeploymentDashboardResponse):
```typescript
{
  coverage: {
    totalPatches: 1234,
    deployedPatches: 890,
    pendingPatches: 250,
    failedPatches: 94,
    deploymentPercentage: 72.2,
    byEcosystem: { "Windows": 1000, "Linux": 234 },
    bySeverity: { "CRITICAL": 100, "HIGH": 300, "MEDIUM": 500, "LOW": 334 },
    bySourceSystem: [
      { sourceSystem: "SCCM", totalPatches: 900, deployedPatches: 700, deploymentPercentage: 77.8, lastSyncSeconds: 3600 },
      { sourceSystem: "BIGFIX", totalPatches: 200, deployedPatches: 150, deploymentPercentage: 75.0, lastSyncSeconds: 7200 }
    ]
  },
  autoResolution: {
    totalAutoResolved: 450,
    uniqueCvesResolved: 200,
    findingsResolvedThisWeek: 45,
    averageResolutionTimeHours: 12.5
  },
  health: {
    status: "EXCELLENT",  // EXCELLENT, GOOD, FAIR, POOR
    score: 95,  // 0-100
    recommendation: "Continue current deployment pace",
    warnings: []
  },
  topPatches: [
    { fixId: "fix-1", title: "KB5027398", sourceSystem: "SCCM", severity: "CRITICAL", 
      applicableAssets: 500, deployedAssets: 450, deploymentPercentage: 90.0, ecosystem: "Windows" }
  ],
  recentActivity: [
    { type: "DEPLOYED", description: "KB5027398 deployed to 50 assets", timestampSeconds: 1696898400, metadata: {} }
  ],
  recommendations: [
    "Deploy KB5027390 to reduce CRITICAL vulnerability exposure by 30%",
    "Investigate failed deployments on 5 assets"
  ]
}
```

**Create types file:**
```typescript
// src/features/patch-management/types.ts
export interface PatchCoverageMetrics {
  totalPatches: number;
  deployedPatches: number;
  pendingPatches: number;
  failedPatches: number;
  deploymentPercentage: number;
  byEcosystem: Record<string, number>;
  bySeverity: Record<string, number>;
  bySourceSystem: SourceSystemMetrics[];
}

export interface SourceSystemMetrics {
  sourceSystem: string;
  totalPatches: number;
  deployedPatches: number;
  deploymentPercentage: number;
  lastSyncSeconds: number;
}

export interface AutoResolutionStats {
  totalAutoResolved: number;
  uniqueCvesResolved: number;
  findingsResolvedThisWeek: number;
  averageResolutionTimeHours: number;
}

export interface HealthScore {
  status: 'EXCELLENT' | 'GOOD' | 'FAIR' | 'POOR';
  score: number;
  recommendation: string;
  warnings: string[];
}

export interface PatchDeploymentDashboardResponse {
  coverage: PatchCoverageMetrics;
  autoResolution: AutoResolutionStats;
  health: HealthScore;
  topPatches: PatchSummary[];
  recentActivity: RecentActivity[];
  recommendations: string[];
}

export interface PatchSummary {
  fixId: string;
  title: string;
  sourceSystem: string;
  severity: string;
  applicableAssets: number;
  deployedAssets: number;
  deploymentPercentage: number;
  ecosystem: string;
}

export interface RecentActivity {
  type: string;
  description: string;
  timestampSeconds: number;
  metadata: Record<string, unknown>;
}
```

**Owner:** Frontend Engineer  
**Time:** 1 hour  
**Deliverable:** TypeScript types defined

### Task 1.2: Create API Hook

**File:** `src/features/patch-management/hooks/usePatchDashboardQuery.ts`

```typescript
import { useQuery } from '@tanstack/react-query';
import { apiClient } from '@/api/client';
import { PatchDeploymentDashboardResponse } from '../types';

export function usePatchDashboardQuery() {
  return useQuery({
    queryKey: ['patch-dashboard'],
    queryFn: async () => {
      const response = await apiClient.get<PatchDeploymentDashboardResponse>(
        '/patches/dashboard/overview'
      );
      return response.data;
    },
    staleTime: 5 * 60 * 1000,  // 5 minutes
    refetchInterval: 30 * 1000,  // Refetch every 30 seconds
  });
}
```

**Owner:** Frontend Engineer  
**Time:** 30 minutes  
**Deliverable:** Query hook created

### Task 1.3: Build Dashboard Components

**Main Dashboard Component:**
```typescript
// src/features/patch-management/pages/PatchDashboard.tsx
import React from 'react';
import { usePatchDashboardQuery } from '../hooks/usePatchDashboardQuery';
import { HealthScoreCard } from '../components/HealthScoreCard';
import { CoverageMetricsSection } from '../components/CoverageMetricsSection';
import { TopPatchesSection } from '../components/TopPatchesSection';
import { RecentActivitySection } from '../components/RecentActivitySection';
import { RecommendationsSection } from '../components/RecommendationsSection';

export function PatchDashboard() {
  const { data, isLoading, isError, error } = usePatchDashboardQuery();

  if (isLoading) {
    return <div>Loading patch dashboard...</div>;
  }

  if (isError) {
    return <div>Error loading dashboard: {error?.message}</div>;
  }

  if (!data) {
    return <div>No data available</div>;
  }

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-3xl font-bold">Patch Management Dashboard</h1>
      
      {/* Health Score - Top Priority */}
      <HealthScoreCard health={data.health} />
      
      {/* Coverage Metrics - Main Section */}
      <CoverageMetricsSection coverage={data.coverage} />
      
      {/* Top Patches - Important Actionable Items */}
      <TopPatchesSection patches={data.topPatches} />
      
      {/* Recent Activity - Audit Trail */}
      <RecentActivitySection activity={data.recentActivity} />
      
      {/* Recommendations - Guidance */}
      <RecommendationsSection recommendations={data.recommendations} />
      
      {/* Auto-Resolution Stats - Summary */}
      <div className="bg-white rounded shadow p-4">
        <h3 className="text-lg font-semibold mb-4">Auto-Resolution Stats</h3>
        <div className="grid grid-cols-4 gap-4">
          <div>
            <div className="text-3xl font-bold">{data.autoResolution.totalAutoResolved}</div>
            <div className="text-gray-600">Total Auto-Resolved</div>
          </div>
          <div>
            <div className="text-3xl font-bold">{data.autoResolution.uniqueCvesResolved}</div>
            <div className="text-gray-600">Unique CVEs Resolved</div>
          </div>
          <div>
            <div className="text-3xl font-bold">{data.autoResolution.findingsResolvedThisWeek}</div>
            <div className="text-gray-600">Resolved This Week</div>
          </div>
          <div>
            <div className="text-3xl font-bold">{data.autoResolution.averageResolutionTimeHours.toFixed(1)}h</div>
            <div className="text-gray-600">Avg Resolution Time</div>
          </div>
        </div>
      </div>
    </div>
  );
}
```

**Sub-Components:**

1. **HealthScoreCard.tsx**
```typescript
interface HealthScoreCardProps {
  health: HealthScore;
}

export function HealthScoreCard({ health }: HealthScoreCardProps) {
  const getColorClass = (status: string) => {
    switch (status) {
      case 'EXCELLENT': return 'bg-green-100 text-green-900';
      case 'GOOD': return 'bg-blue-100 text-blue-900';
      case 'FAIR': return 'bg-yellow-100 text-yellow-900';
      case 'POOR': return 'bg-red-100 text-red-900';
      default: return 'bg-gray-100 text-gray-900';
    }
  };

  return (
    <div className={`rounded shadow p-6 ${getColorClass(health.status)}`}>
      <div className="flex justify-between items-center">
        <div>
          <h2 className="text-2xl font-bold">{health.status}</h2>
          <p className="text-lg mt-2">{health.recommendation}</p>
        </div>
        <div className="text-4xl font-bold">{health.score}/100</div>
      </div>
      {health.warnings.length > 0 && (
        <div className="mt-4 pt-4 border-t">
          <h4 className="font-semibold">Warnings:</h4>
          <ul className="list-disc ml-5">
            {health.warnings.map((w, i) => <li key={i}>{w}</li>)}
          </ul>
        </div>
      )}
    </div>
  );
}
```

2. **CoverageMetricsSection.tsx**
```typescript
interface CoverageMetricsSectionProps {
  coverage: PatchCoverageMetrics;
}

export function CoverageMetricsSection({ coverage }: CoverageMetricsSectionProps) {
  return (
    <div className="space-y-4">
      <h2 className="text-2xl font-bold">Coverage Metrics</h2>
      
      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard 
          label="Total Patches" 
          value={coverage.totalPatches} 
          color="bg-blue-50"
        />
        <MetricCard 
          label="Deployed" 
          value={coverage.deployedPatches} 
          color="bg-green-50"
        />
        <MetricCard 
          label="Pending" 
          value={coverage.pendingPatches} 
          color="bg-yellow-50"
        />
        <MetricCard 
          label="Failed" 
          value={coverage.failedPatches} 
          color="bg-red-50"
        />
      </div>
      
      {/* Deployment Percentage Bar */}
      <div className="bg-white rounded shadow p-4">
        <div className="flex justify-between mb-2">
          <span className="font-semibold">Deployment Progress</span>
          <span className="text-lg font-bold">{coverage.deploymentPercentage.toFixed(1)}%</span>
        </div>
        <div className="w-full bg-gray-200 rounded-full h-4">
          <div 
            className="bg-green-500 h-4 rounded-full"
            style={{ width: `${coverage.deploymentPercentage}%` }}
          />
        </div>
      </div>
      
      {/* By Ecosystem */}
      <div className="bg-white rounded shadow p-4">
        <h3 className="font-semibold mb-3">By Ecosystem</h3>
        <div className="space-y-2">
          {Object.entries(coverage.byEcosystem).map(([eco, count]) => (
            <div key={eco} className="flex justify-between">
              <span>{eco}</span>
              <span className="font-semibold">{count} patches</span>
            </div>
          ))}
        </div>
      </div>
      
      {/* By Severity */}
      <div className="bg-white rounded shadow p-4">
        <h3 className="font-semibold mb-3">By Severity</h3>
        <div className="space-y-2">
          {Object.entries(coverage.bySeverity).map(([sev, count]) => (
            <div key={sev} className="flex justify-between">
              <span className="font-semibold">{sev}</span>
              <span>{count} patches</span>
            </div>
          ))}
        </div>
      </div>
      
      {/* By Source System */}
      <div className="bg-white rounded shadow p-4">
        <h3 className="font-semibold mb-3">By Source System</h3>
        <table className="w-full">
          <thead>
            <tr className="border-b">
              <th className="text-left">System</th>
              <th className="text-right">Total</th>
              <th className="text-right">Deployed</th>
              <th className="text-right">%</th>
              <th className="text-right">Last Sync</th>
            </tr>
          </thead>
          <tbody>
            {coverage.bySourceSystem.map(sys => (
              <tr key={sys.sourceSystem} className="border-b">
                <td>{sys.sourceSystem}</td>
                <td className="text-right">{sys.totalPatches}</td>
                <td className="text-right">{sys.deployedPatches}</td>
                <td className="text-right">{sys.deploymentPercentage.toFixed(1)}%</td>
                <td className="text-right">{formatSeconds(sys.lastSyncSeconds)} ago</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}

function MetricCard({ label, value, color }: any) {
  return (
    <div className={`rounded shadow p-4 ${color}`}>
      <div className="text-3xl font-bold">{value}</div>
      <div className="text-gray-600 mt-1">{label}</div>
    </div>
  );
}
```

3. **TopPatchesSection.tsx** and **RecentActivitySection.tsx** — Similar pattern

**Owner:** Frontend Engineer  
**Time:** 4 hours  
**Deliverable:** Dashboard page fully built with all components

### Task 1.4: Test Dashboard Responsiveness

**Browser Testing Checklist:**
```
Desktop (1920x1080):
- [ ] All cards visible without scrolling
- [ ] Charts/tables readable
- [ ] No overflow or cutoff elements

Tablet (768x1024):
- [ ] Cards stack vertically
- [ ] Tables readable with horizontal scroll if needed
- [ ] Touch targets adequate (>44px)

Mobile (375x812):
- [ ] Single column layout
- [ ] All content accessible
- [ ] Metrics cards stack properly
```

**Owner:** QA Engineer  
**Time:** 1 hour  
**Deliverable:** Responsive design verified

---

## Day 13: Drill-Down & Configuration Pages

### Task 2.1: Patch Deployment Drill-Down Page

**File:** `src/features/patch-management/pages/PatchDeploymentDrill Down.tsx`

**Page Structure:**
```typescript
export function PatchDeploymentDrillDown() {
  const { fixId } = useParams();
  const { data: patch } = usePatchDetailsQuery(fixId);
  const { data: deploymentStatus } = usePatchDeploymentStatusQuery(fixId);
  const [filter, setFilter] = useState('ALL');
  const [searchTerm, setSearchTerm] = useState('');

  return (
    <div className="space-y-4 p-6">
      <h1 className="text-2xl font-bold">{patch?.title}</h1>
      
      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4">
        <MetricCard label="Applicable" value={patch?.applicableAssets} />
        <MetricCard label="Deployed" value={patch?.deployedAssets} />
        <MetricCard label="Pending" value={patch?.pendingAssets} />
        <MetricCard label="Failed" value={patch?.failedAssets} />
      </div>
      
      {/* Filter & Search */}
      <div className="flex gap-4">
        <select onChange={e => setFilter(e.target.value)}>
          <option value="ALL">All Statuses</option>
          <option value="DEPLOYED">Deployed</option>
          <option value="PENDING">Pending</option>
          <option value="FAILED">Failed</option>
        </select>
        <input 
          type="text" 
          placeholder="Search assets..." 
          onChange={e => setSearchTerm(e.target.value)}
        />
      </div>
      
      {/* Asset Status Table */}
      <table className="w-full border">
        <thead>
          <tr className="bg-gray-100">
            <th>Asset Name</th>
            <th>Status</th>
            <th>Deployed At</th>
            <th>Notes</th>
          </tr>
        </thead>
        <tbody>
          {deploymentStatus
            ?.filter(s => filter === 'ALL' || s.deploymentStatus === filter)
            .filter(s => searchTerm === '' || s.assetName.includes(searchTerm))
            .map(status => (
              <tr key={status.assetId} className="border-b">
                <td className="p-2">{status.assetName}</td>
                <td className="p-2">
                  <StatusBadge status={status.deploymentStatus} />
                </td>
                <td className="p-2">{formatDate(status.deployedAt)}</td>
                <td className="p-2">{status.notes}</td>
              </tr>
            ))}
        </tbody>
      </table>
    </div>
  );
}
```

**Owner:** Frontend Engineer  
**Time:** 2 hours  
**Deliverable:** Drill-down page complete

### Task 2.2: Connector Configuration UI

**File:** `src/features/patch-management/pages/ConnectorConfiguration.tsx`

**Page Structure:**
```typescript
export function ConnectorConfiguration() {
  const { data: connectors } = useConnectorsListQuery();
  const syncMutation = useTriggerConnectorSyncMutation();

  return (
    <div className="space-y-6 p-6">
      <h1 className="text-2xl font-bold">Patch Connectors</h1>
      
      <div className="grid grid-cols-3 gap-4">
        {connectors?.map(connector => (
          <ConnectorCard 
            key={connector.connectorType}
            connector={connector}
            onSync={() => syncMutation.mutate(connector.connectorType)}
          />
        ))}
      </div>
    </div>
  );
}

function ConnectorCard({ connector, onSync }: any) {
  const { data: history } = useSyncHistoryQuery(connector.connectorType);
  
  return (
    <div className="border rounded shadow p-4">
      <h3 className="text-lg font-bold">{connector.name}</h3>
      <p className="text-gray-600">Type: {connector.connectorType}</p>
      
      <div className="mt-4 space-y-2">
        <div>Last Sync: {formatDate(connector.lastSyncTime)}</div>
        <div>Status: <StatusBadge status={connector.status} /></div>
        <div>Patches: {connector.patchCount}</div>
      </div>
      
      <button 
        onClick={onSync}
        className="mt-4 w-full bg-blue-500 text-white p-2 rounded hover:bg-blue-600"
      >
        Sync Now
      </button>
      
      {/* Recent Sync History */}
      <div className="mt-4 text-sm">
        <h4 className="font-semibold mb-2">Recent Syncs:</h4>
        <div className="space-y-1">
          {history?.slice(0, 5).map(sync => (
            <div key={sync.id} className="flex justify-between">
              <span>{formatDate(sync.timestamp)}</span>
              <span className={sync.status === 'SUCCESS' ? 'text-green-600' : 'text-red-600'}>
                {sync.status}
              </span>
            </div>
          ))}
        </div>
      </div>
    </div>
  );
}
```

**Owner:** Frontend Engineer  
**Time:** 2 hours  
**Deliverable:** Configuration UI complete

---

## Day 14: Finding Detail Page Integration

### Task 3.1: Add Patch Information to Finding Detail

**Modification:** `src/features/findings/pages/FindingDetailPage.tsx`

**Add patch section:**
```typescript
function FindingDetailPage() {
  const { finding } = useFindingDetailQuery();
  const { patches } = useFindingPatchesQuery(finding?.cveId);

  return (
    <div>
      {/* Existing finding content */}
      
      {/* New Patch Section */}
      {patches && patches.length > 0 && (
        <div className="bg-green-50 border border-green-200 rounded p-4 mt-6">
          <h3 className="text-lg font-bold text-green-900 mb-3">
            ✓ Patches Available for Remediation
          </h3>
          
          <div className="space-y-3">
            {patches.map(patch => (
              <div key={patch.fixId} className="bg-white rounded p-3 border border-green-100">
                <div className="flex justify-between">
                  <div>
                    <h4 className="font-semibold">{patch.title}</h4>
                    <p className="text-sm text-gray-600">
                      {patch.sourceSystem} | {patch.ecosystem}
                    </p>
                  </div>
                  <div className="text-right">
                    <div className="text-2xl font-bold text-green-600">
                      {patch.deploymentPercentage.toFixed(0)}%
                    </div>
                    <div className="text-xs text-gray-600">
                      Deployed to {patch.deployedAssets} of {patch.applicableAssets}
                    </div>
                  </div>
                </div>
                
                <button 
                  onClick={() => navigateToDrillDown(patch.fixId)}
                  className="mt-2 text-blue-600 hover:underline text-sm"
                >
                  View deployment details →
                </button>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
```

**Owner:** Frontend Engineer  
**Time:** 1 hour  
**Deliverable:** Finding integration complete

---

## Day 15: End-to-End Testing

### Task 4.1: Browser Testing

**Chrome Testing:**
```bash
# Open Chrome DevTools
# Test: Patch Dashboard page loads in <2 seconds
# Test: All metrics display correctly
# Test: Click on patch → drill-down page loads
# Test: Filter/search on drill-down page works
# Test: No console errors
```

**Firefox & Safari Testing:**
- Same test sequence in Firefox and Safari
- Verify responsive design
- Check for browser-specific CSS issues

**Owner:** QA Engineer  
**Time:** 2 hours  
**Deliverable:** All pages tested in 3 browsers, no errors

### Task 4.2: Performance Validation

**Lighthouse Audit:**
```bash
# Chrome DevTools → Lighthouse
# Target scores:
# - Performance: >80
# - Accessibility: >90
# - Best Practices: >90
# - SEO: >80
```

**Load Time Targets:**
- Dashboard page: <2s
- Drill-down page: <1s
- Configuration page: <1s

**Owner:** Performance Engineer  
**Time:** 1 hour  
**Deliverable:** Lighthouse scores captured

### Task 4.3: Functionality Verification

**Checklist:**
```
Dashboard:
- [ ] All metrics display
- [ ] Charts render correctly
- [ ] Recommendations visible
- [ ] Recent activity shows events
- [ ] Health score accurate

Drill-Down:
- [ ] Asset list loads
- [ ] Filters work (by status)
- [ ] Search works (by name)
- [ ] Sort by column works
- [ ] Pagination works (if >100 assets)

Configuration:
- [ ] 3 connectors listed
- [ ] Test connection works
- [ ] Sync trigger works
- [ ] History shows past syncs
- [ ] Loading states visible

Finding Integration:
- [ ] Patch badge shows on finding
- [ ] Deployment % accurate
- [ ] Link to drill-down works
```

**Owner:** QA Engineer  
**Time:** 2 hours  
**Deliverable:** All functionality verified

---

## Week 3 Success Criteria

| Milestone | Status |
|-----------|--------|
| Patch Dashboard built | ⏳ |
| Drill-Down page built | ⏳ |
| Configuration UI built | ⏳ |
| Finding integration done | ⏳ |
| Responsive design verified | ⏳ |
| Browser compatibility tested | ⏳ |
| Performance targets met | ⏳ |
| All functionality working | ⏳ |

---

## Sign-Off & Next Steps

**After Week 3 completion:**
- [ ] All dashboard pages built and tested
- [ ] Responsive design working on all devices
- [ ] Browser compatibility verified
- [ ] Performance targets met
- [ ] No console errors or warnings
- [ ] Pull request ready for review

**Proceed to Week 4:** Monitoring & Documentation Setup
