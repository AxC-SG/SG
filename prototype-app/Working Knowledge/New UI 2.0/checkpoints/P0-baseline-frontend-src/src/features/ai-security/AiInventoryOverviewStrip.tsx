import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../../api/client';
import { useActor } from '../auth/context';
import { canUseEntitlement } from '../auth/entitlements';

export function AiInventoryOverviewStrip() {
  const actor = useActor();
  const navigate = useNavigate();
  const entitled = canUseEntitlement(actor, 'ai.security') && actor?.platformScope !== true;
  const summaryQuery = useQuery({
    queryKey: ['ai-security-summary'],
    queryFn: api.getAiSecuritySummary,
    enabled: entitled,
  });
  const coverageQuery = useQuery({
    queryKey: ['ai-grid-coverage'],
    queryFn: api.getAiGridCoverage,
    enabled: entitled,
  });
  if (!entitled) return null;

  const summary = summaryQuery.data;
  const other = summary?.artifactCounts.OTHER_AI_ARTIFACT ?? 0;
  return (
    <section className="ai-overview-strip">
      <div>
        <span className="ai-security-kicker">AI inventory</span>
        <h3>Cloud AI estate coverage</h3>
      </div>
      <button type="button" onClick={() => navigate('/inventory/ai/agents')}><strong>{summary?.logicalAgentCount ?? 0}</strong><span>Agents</span></button>
      <button type="button" onClick={() => navigate('/inventory/ai')}><strong>{summary?.artifactCounts.AI_MODEL ?? 0}</strong><span>Models</span></button>
      <button type="button" onClick={() => navigate('/inventory/ai')}><strong>{other}</strong><span>Other artifacts</span></button>
      <button type="button" onClick={() => navigate('/findings/ai')} className="risk"><strong>{summary?.openFindings ?? 0}</strong><span>Open findings</span></button>
      <button type="button" onClick={() => navigate('/inventory/ai')}>
        <strong>{(summary?.incompleteScopes ?? 0) + (coverageQuery.data?.unsupported ?? 0)}</strong>
        <span>Incomplete or unsupported</span>
      </button>
    </section>
  );
}
