import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
import { AsyncSection } from '../components/AsyncSection';
import { InventoryShell } from '../features/inventory/InventoryShell';
import { pathForAiBomDeclaredResourceDetail } from '../app/routes';

const PRIORITY_ORDER: Record<string, number> = { HIGH: 0, MEDIUM: 1, LOW: 2 };

export function AiBomDeclaredResourcesPage() {
  const navigate = useNavigate();
  const setupActionsQuery = useQuery({
    queryKey: ['ai-bom-setup-actions'],
    queryFn: api.listAiBomSetupActions,
  });
  const resourcesQuery = useQuery({
    queryKey: ['ai-bom-declared-resources'],
    queryFn: () => api.listAiBomDeclaredResources(),
  });

  const setupActions = [...(setupActionsQuery.data ?? [])].sort(
    (a, b) => (PRIORITY_ORDER[a.priority] ?? 3) - (PRIORITY_ORDER[b.priority] ?? 3));
  const resources = resourcesQuery.data ?? [];

  return (
    <InventoryShell
      eyebrow="AI-BOM declared inventory"
      title="Declared AI Resources"
      description="Models and datasets an uploaded AI-BOM declared, and their deployment-linking coverage."
      legacyClassName="ai-security-page"
    >
      <section className="panel ai-security-table-panel">
        <div className="panel-header">
          <div>
            <h3>Coverage Setup Actions</h3>
            <p className="panel-caption">
              Work a person needs to resolve so declared resources reflect a real deployment.
              Never a policy violation.
            </p>
          </div>
        </div>
        <AsyncSection
          state={!setupActionsQuery.data ? (setupActionsQuery.isError ? 'error' : 'pending') : setupActions.length === 0 ? 'empty' : 'ready'}
          loadingLabel="Loading setup actions…"
          emptyMessage="No outstanding AI-BOM coverage work."
          errorMessage="Coverage setup actions could not be loaded."
          refreshError={setupActionsQuery.isError && setupActionsQuery.data ? 'Setup actions could not be refreshed; showing the last loaded list.' : undefined}
          onRetry={() => void setupActionsQuery.refetch()}
          retryLabel="Retry setup actions"
          retrying={setupActionsQuery.isFetching}
        >
          <table className="data-table">
            <thead><tr><th>Priority</th><th>Category</th><th>Title</th><th>Detail</th></tr></thead>
            <tbody>
              {setupActions.map((action) => (
                <tr
                  key={`${action.category}-${action.evidenceId}`}
                  onClick={() => navigate(pathForAiBomDeclaredResourceDetail(action.evidenceId))}
                >
                  <td><strong>{action.priority}</strong></td>
                  <td>{action.category.replace(/_/g, ' ')}</td>
                  <td>{action.title}</td>
                  <td>{action.detail}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </AsyncSection>
      </section>

      <section className="panel ai-security-table-panel">
        <div className="panel-header">
          <div>
            <h3>Declared Resources</h3>
            <p className="panel-caption">Every model or dataset declared by an uploaded AI-BOM.</p>
          </div>
        </div>
        <AsyncSection
          state={!resourcesQuery.data ? (resourcesQuery.isError ? 'error' : 'pending') : resources.length === 0 ? 'empty' : 'ready'}
          loadingLabel="Loading declared resources…"
          emptyMessage="No AI-BOM has declared a model or dataset yet."
          errorMessage="Declared resources could not be loaded."
          refreshError={resourcesQuery.isError && resourcesQuery.data ? 'Declared resources could not be refreshed; showing the last loaded list.' : undefined}
          onRetry={() => void resourcesQuery.refetch()}
          retryLabel="Retry declared resources"
          retrying={resourcesQuery.isFetching}
        >
          <table className="data-table">
            <thead><tr><th>Name</th><th>Kind</th><th>Version</th><th>Deployment</th><th>Last declared</th></tr></thead>
            <tbody>
              {resources.map((resource) => (
                <tr key={resource.id} onClick={() => navigate(pathForAiBomDeclaredResourceDetail(resource.id))}>
                  <td>{resource.name}</td>
                  <td>{resource.resourceKind}</td>
                  <td>{resource.version ?? '—'}</td>
                  <td><span className="status-pill">{resource.deploymentState}</span></td>
                  <td>{new Date(resource.lastDeclaredAt).toLocaleString()}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </AsyncSection>
      </section>
    </InventoryShell>
  );
}
