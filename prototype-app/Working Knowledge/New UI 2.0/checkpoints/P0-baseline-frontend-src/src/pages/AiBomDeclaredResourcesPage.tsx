import { useQuery } from '@tanstack/react-query';
import { useNavigate } from 'react-router-dom';
import { api } from '../api/client';
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
        {setupActionsQuery.isLoading ? (
          <div className="empty-state"><p>Loading setup actions…</p></div>
        ) : setupActions.length === 0 ? (
          <div className="empty-state"><p>No outstanding AI-BOM coverage work.</p></div>
        ) : (
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
        )}
      </section>

      <section className="panel ai-security-table-panel">
        <div className="panel-header">
          <div>
            <h3>Declared Resources</h3>
            <p className="panel-caption">Every model or dataset declared by an uploaded AI-BOM.</p>
          </div>
        </div>
        {resourcesQuery.isLoading ? (
          <div className="empty-state"><p>Loading declared resources…</p></div>
        ) : resources.length === 0 ? (
          <div className="empty-state"><p>No AI-BOM has declared a model or dataset yet.</p></div>
        ) : (
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
        )}
      </section>
    </InventoryShell>
  );
}
