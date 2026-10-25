import React from 'react';
import { useSearchParams } from 'react-router-dom';
import { api } from '../api/client';

export type IngestionMode = 'endpoint' | 'github';
type Props = {
  onDone?: () => void;
  initialMode?: IngestionMode;
  hideModeToggle?: boolean;
  title?: string;
  caption?: string;
};
const MODE_QUERY_KEY = 'ingestMode';

function isMode(value: string | null): value is IngestionMode {
  return value === 'endpoint' || value === 'github';
}

export function IngestionPage({
  onDone,
  initialMode,
  hideModeToggle = false,
  title = 'SBOM Ingestion',
  caption = 'Fetch SBOM JSON from authenticated API or GitHub sources with evidence retention'
}: Props) {
  const [searchParams, setSearchParams] = useSearchParams();
  const queryMode = React.useMemo<IngestionMode>(() => {
    const value = searchParams.get(MODE_QUERY_KEY);
    return isMode(value) ? value : 'endpoint';
  }, [searchParams]);
  const mode = initialMode ?? queryMode;
  const [assetType, setAssetType] = React.useState<'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE'>('APPLICATION');
  const [assetName, setAssetName] = React.useState('');
  const [assetIdentifier, setAssetIdentifier] = React.useState('');
  const [showGithubAssetOverrides, setShowGithubAssetOverrides] = React.useState(false);

  const [sourceUrl, setSourceUrl] = React.useState('');
  const [sourceLabel, setSourceLabel] = React.useState('');
  const [authorizationHeader, setAuthorizationHeader] = React.useState('');
  const [showAuthorizationHeader, setShowAuthorizationHeader] = React.useState(false);

  const [githubOwner, setGithubOwner] = React.useState('');
  const [githubRepo, setGithubRepo] = React.useState('');

  const [result, setResult] = React.useState('');
  const [error, setError] = React.useState('');
  const [loading, setLoading] = React.useState(false);
  const [wizardStep, setWizardStep] = React.useState<1 | 2 | 3>(1);
  const [wizardStepError, setWizardStepError] = React.useState('');

  React.useEffect(() => {
    setError('');
  }, []);

  const setMode = React.useCallback((nextMode: IngestionMode) => {
    if (initialMode || hideModeToggle) {
      return;
    }
    const nextSearchParams = new URLSearchParams(searchParams);
    if (nextMode === 'endpoint') {
      nextSearchParams.delete(MODE_QUERY_KEY);
    } else {
      nextSearchParams.set(MODE_QUERY_KEY, nextMode);
    }
    if (nextSearchParams.toString() !== searchParams.toString()) {
      setSearchParams(nextSearchParams, { replace: true });
    }
  }, [hideModeToggle, initialMode, searchParams, setSearchParams]);

  const validateCommon = (currentMode: IngestionMode): string | null => {
    if (currentMode === 'github') {
      return null;
    }
    if (!assetName.trim()) return 'Asset Name is required';
    if (!assetIdentifier.trim()) return 'Asset Identifier is required';
    return null;
  };

  const submit = async (): Promise<void> => {
    const commonError = validateCommon(mode);
    if (commonError) {
      setError(commonError);
      return;
    }

    setError('');
    setResult('');
    const githubOwnerValue = githubOwner.trim();
    const githubRepoValue = githubRepo.trim();
    if (mode === 'github') {
      if (!githubOwnerValue) {
        setError('GitHub owner/account is required in GitHub mode');
        return;
      }
      if (!githubRepoValue) {
        const proceed = window.confirm(
          `Repository is empty. This will ingest SBOMs for all repositories under "${githubOwnerValue}". Continue?`
        );
        if (!proceed) {
          return;
        }
      }
    }
    setLoading(true);
    try {
      if (mode === 'endpoint') {
        if (!sourceUrl.trim()) {
          throw new Error('Source URL is required in endpoint mode');
        }
        const response = await api.fetchSbomFromEndpoint({
          assetType,
          assetName: assetName.trim(),
          assetIdentifier: assetIdentifier.trim(),
          sourceUrl: sourceUrl.trim(),
          sourceLabel: sourceLabel.trim() || undefined,
          authorizationHeader: authorizationHeader.trim() || undefined
        });
        setResult(`Ingested successfully. Components: ${response.componentsIngested}`);
      } else {
        const response = await api.queueGithubRepositoryRun({
          owner: githubOwnerValue,
          repo: githubRepoValue || undefined,
          includeAllRepos: !githubRepoValue,
          assetType: showGithubAssetOverrides ? assetType : undefined,
          assetName: showGithubAssetOverrides && githubRepoValue ? assetName.trim() || undefined : undefined,
          assetIdentifier: showGithubAssetOverrides && githubRepoValue ? assetIdentifier.trim() || undefined : undefined
        });
        setResult(
          `GitHub ingestion queued as run ${response.runId}. Track progress in Connect > Inventory Run Queue.`
        );
      }

      onDone?.();
    } catch (e) {
      setError(`SBOM ingestion failed: ${e instanceof Error ? e.message : String(e)}`);
    } finally {
      setLoading(false);
    }
  };

  const isGithubSingleRepo = githubRepo.trim().length > 0;

  const validateAndAdvance = (): void => {
    setWizardStepError('');
    if (wizardStep === 1) {
      if (mode === 'endpoint' && !sourceUrl.trim()) { setWizardStepError('SBOM Endpoint URL is required'); return; }
      if (mode === 'github' && !githubOwner.trim()) { setWizardStepError('GitHub Owner is required'); return; }
      setWizardStep(2);
    } else if (wizardStep === 2) {
      if (mode !== 'github') {
        if (!assetName.trim()) { setWizardStepError('Asset Name is required'); return; }
        if (!assetIdentifier.trim()) { setWizardStepError('Asset Identifier is required'); return; }
      }
      setWizardStep(3);
    }
  };

  const WIZARD_STEP_LABELS = ['Source', 'Asset Context', 'Review & Ingest'] as const;

  return (
    <div className="panel">
      <div className="panel-header">
        <h3>{title}</h3>
        <span className="panel-caption">{caption}</span>
      </div>

      {hideModeToggle ? (
        /* ── WIZARD MODE (used from connector drawer) ── */
        <div className="section-block">
          {/* Step indicator */}
          <div className="wizard-steps">
            {WIZARD_STEP_LABELS.map((label, i) => {
              const stepNum = (i + 1) as 1 | 2 | 3;
              const isDone = wizardStep > stepNum;
              const isActive = wizardStep === stepNum;
              return (
                <React.Fragment key={label}>
                  {i > 0 && <div className={`wizard-connector${isDone ? ' wizard-connector--done' : ''}`} />}
                  <div className={`wizard-step${isActive ? ' wizard-step--active' : ''}${isDone ? ' wizard-step--done' : ''}`}>
                    <span className="wizard-step-dot">{isDone ? '✓' : stepNum}</span>
                    <span className="wizard-step-label">{label}</span>
                  </div>
                </React.Fragment>
              );
            })}
          </div>

          {/* Step 1: Source */}
          {wizardStep === 1 && (
            <div className="wizard-step-body form-grid ingestion-grid">
              {mode === 'endpoint' && (
                <>
                  <label>SBOM Endpoint URL
                    <input value={sourceUrl} onChange={(e) => setSourceUrl(e.target.value)} placeholder="https://tool.example.com/api/sbom/project-a" />
                  </label>
                  <label>Source Label (optional)
                    <input value={sourceLabel} onChange={(e) => setSourceLabel(e.target.value)} placeholder="Prod CycloneDX Generator" />
                  </label>
                  <label>Authorization Header (optional)
                    <div className="secure-input-row">
                      <input type={showAuthorizationHeader ? 'text' : 'password'} value={authorizationHeader} onChange={(e) => setAuthorizationHeader(e.target.value)} placeholder="Bearer <token> or Basic <base64>" autoComplete="off" />
                      <button type="button" className="btn btn-secondary btn-inline" onClick={() => setShowAuthorizationHeader((v) => !v)}>
                        {showAuthorizationHeader ? 'Hide' : 'Show'}
                      </button>
                    </div>
                  </label>
                </>
              )}
              {mode === 'github' && (
                <>
                  <label>GitHub Owner
                    <input value={githubOwner} onChange={(e) => setGithubOwner(e.target.value)} placeholder="org-name" />
                  </label>
                  <label>GitHub Repo (optional)
                    <input value={githubRepo} onChange={(e) => setGithubRepo(e.target.value)} placeholder="service-repo (leave empty to ingest all)" />
                  </label>
                  <div className="inline-note">
                    If repo is left empty, the app confirms and ingests SBOMs for all repositories in the owner account.
                  </div>
                </>
              )}
            </div>
          )}

          {/* Step 2: Asset Context */}
          {wizardStep === 2 && (
            <div className="wizard-step-body">
              {mode === 'github' ? (
                <>
                  <div className="inline-note">
                    Each repository is automatically classified as <span className="mono">APPLICATION</span> with identifier <span className="mono">github:owner/repo</span>. Expand below to override.
                  </div>
                  <div className="button-row form-submit-row">
                    <button type="button" className="btn btn-secondary" onClick={() => setShowGithubAssetOverrides((v) => !v)}>
                      {showGithubAssetOverrides ? 'Hide Overrides' : 'Customize Asset Context'}
                    </button>
                  </div>
                  {showGithubAssetOverrides && (
                    <div className="form-grid ingestion-grid">
                      <label>Asset Type Override
                        <select value={assetType} onChange={(e) => setAssetType(e.target.value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE')}>
                          <option value="APPLICATION">Application</option>
                          <option value="HOST">Host</option>
                          <option value="CONTAINER_IMAGE">Container Image</option>
                        </select>
                      </label>
                      {isGithubSingleRepo ? (
                        <>
                          <label>Asset Name Override (optional)
                            <input value={assetName} onChange={(e) => setAssetName(e.target.value)} placeholder="repo-name default" />
                          </label>
                          <label>Asset Identifier Override (optional)
                            <input value={assetIdentifier} onChange={(e) => setAssetIdentifier(e.target.value)} placeholder="github:owner/repo default" />
                          </label>
                        </>
                      ) : (
                        <div className="inline-note">
                          Account-wide ingestion preserves <span className="mono">org/repo</span> lineage — name and identifier are set per repository.
                        </div>
                      )}
                    </div>
                  )}
                </>
              ) : (
                <div className="form-grid ingestion-grid">
                  <label>Asset Type
                    <select value={assetType} onChange={(e) => setAssetType(e.target.value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE')}>
                      <option value="APPLICATION">Application</option>
                      <option value="HOST">Host</option>
                      <option value="CONTAINER_IMAGE">Container Image</option>
                    </select>
                  </label>
                  <label>Asset Name
                    <input value={assetName} onChange={(e) => setAssetName(e.target.value)} placeholder="payments-api-prod" />
                  </label>
                  <label>Asset Identifier
                    <input value={assetIdentifier} onChange={(e) => setAssetIdentifier(e.target.value)} placeholder="host-001 or image digest" />
                  </label>
                </div>
              )}
            </div>
          )}

          {/* Step 3: Review & Ingest */}
          {wizardStep === 3 && (
            <div className="wizard-step-body">
              <table className="wizard-review-table">
                <tbody>
                  {(mode === 'endpoint'
                    ? [
                        { label: 'Source', value: 'API Endpoint' },
                        { label: 'URL', value: sourceUrl || '—' },
                        { label: 'Asset Type', value: assetType },
                        { label: 'Asset Name', value: assetName || '—' },
                        { label: 'Asset Identifier', value: assetIdentifier || '—' }
                      ]
                    : [
                        { label: 'Source', value: 'GitHub' },
                        { label: 'Owner', value: githubOwner || '—' },
                        { label: 'Repo', value: githubRepo || 'All repositories' },
                        { label: 'Asset Context', value: showGithubAssetOverrides && assetName ? `${assetName} (${assetIdentifier || 'auto'})` : 'Auto — github:owner/repo' }
                      ]
                  ).map((row) => (
                    <tr key={row.label}>
                      <td className="wizard-review-label">{row.label}</td>
                      <td className="mono">{row.value}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}

          {wizardStepError && <div className="notice error">{wizardStepError}</div>}

          <div className="wizard-nav-row">
            {wizardStep > 1 && (
              <button
                type="button"
                className="btn btn-secondary"
                onClick={() => { setWizardStep((s) => (s - 1) as 1 | 2 | 3); setWizardStepError(''); }}
              >
                ← Back
              </button>
            )}
            {wizardStep < 3 ? (
              <button type="button" className="btn btn-primary" onClick={validateAndAdvance}>
                Next →
              </button>
            ) : (
              <button type="button" className="btn btn-primary" onClick={submit} disabled={loading}>
                {loading ? 'Ingesting...' : 'Ingest SBOM'}
              </button>
            )}
          </div>
        </div>
      ) : (
        /* ── FLAT MODE (standalone page) ── */
        <div className="section-block">
          <div className="mode-toggle">
            <button type="button" className={mode === 'endpoint' ? 'mode-btn active' : 'mode-btn'} onClick={() => setMode('endpoint')}>
              API Endpoint
            </button>
            <button type="button" className={mode === 'github' ? 'mode-btn active' : 'mode-btn'} onClick={() => setMode('github')}>
              GitHub Source
            </button>
          </div>

        <div className="form-grid ingestion-grid">
          {mode !== 'github' && (
            <>
              <label>Asset Type
                <select value={assetType} onChange={(e) => setAssetType(e.target.value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE')}>
                  <option value="APPLICATION">Application</option>
                  <option value="HOST">Host</option>
                  <option value="CONTAINER_IMAGE">Container Image</option>
                </select>
              </label>

              <label>Asset Name
                <input
                  value={assetName}
                  onChange={(e) => setAssetName(e.target.value)}
                  placeholder="payments-api-prod"
                />
              </label>

              <label>Asset Identifier
                <input
                  value={assetIdentifier}
                  onChange={(e) => setAssetIdentifier(e.target.value)}
                  placeholder="host-001 or image digest"
                />
              </label>
            </>
          )}

          {mode === 'endpoint' && (
            <>
              <label>SBOM Endpoint URL
                <input
                  value={sourceUrl}
                  onChange={(e) => setSourceUrl(e.target.value)}
                  placeholder="https://tool.example.com/api/sbom/project-a"
                />
              </label>

              <label>Source Label (optional)
                <input
                  value={sourceLabel}
                  onChange={(e) => setSourceLabel(e.target.value)}
                  placeholder="Prod CycloneDX Generator"
                />
              </label>

              <label>Authorization Header (optional)
                <div className="secure-input-row">
                  <input
                    type={showAuthorizationHeader ? 'text' : 'password'}
                    value={authorizationHeader}
                    onChange={(e) => setAuthorizationHeader(e.target.value)}
                    placeholder="Bearer <token> or Basic <base64>"
                    autoComplete="off"
                  />
                  <button
                    type="button"
                    className="btn btn-secondary btn-inline"
                    onClick={() => setShowAuthorizationHeader((current) => !current)}
                  >
                    {showAuthorizationHeader ? 'Hide' : 'Show'}
                  </button>
                </div>
              </label>
            </>
          )}

          {mode === 'github' && (
            <>
              <label>GitHub Owner
                <input value={githubOwner} onChange={(e) => setGithubOwner(e.target.value)} placeholder="org-name" />
              </label>

              <label>GitHub Repo (optional)
                <input
                  value={githubRepo}
                  onChange={(e) => setGithubRepo(e.target.value)}
                  placeholder="service-repo (leave empty to ingest all repos)"
                />
              </label>

              <div className="inline-note">
                Default asset classification is <span className="mono">APPLICATION</span>. If repo is empty, the app confirms and ingests all
                repositories in the owner account. Each repository is normalized into a unique asset using{' '}
                <span className="mono">github:owner/repo</span>, and org/repo lineage is stored in ingestion evidence.
              </div>

              <div className="button-row form-submit-row">
                <button
                  type="button"
                  className="btn btn-secondary"
                  onClick={() => setShowGithubAssetOverrides((current) => !current)}
                >
                  {showGithubAssetOverrides ? 'Hide Asset Overrides' : 'Show Asset Overrides'}
                </button>
              </div>

              {showGithubAssetOverrides && (
                <>
                  <label>Asset Type Override
                    <select value={assetType} onChange={(e) => setAssetType(e.target.value as 'APPLICATION' | 'HOST' | 'CONTAINER_IMAGE')}>
                      <option value="APPLICATION">Application</option>
                      <option value="HOST">Host</option>
                      <option value="CONTAINER_IMAGE">Container Image</option>
                    </select>
                  </label>
                  {isGithubSingleRepo ? (
                    <>
                      <label>Asset Name Override (optional)
                        <input
                          value={assetName}
                          onChange={(e) => setAssetName(e.target.value)}
                          placeholder="repo-name default"
                        />
                      </label>
                      <label>Asset Identifier Override (optional)
                        <input
                          value={assetIdentifier}
                          onChange={(e) => setAssetIdentifier(e.target.value)}
                          placeholder="github:owner/repo default"
                        />
                      </label>
                    </>
                  ) : (
                    <div className="inline-note">
                      Repo is empty, so account-wide ingestion will always set asset name/identifier per repository to preserve{' '}
                      <span className="mono">org/repo</span> lineage.
                    </div>
                  )}
                </>
              )}

              <div className="inline-note">
                GitHub mode pulls the generated SBOM from <span className="mono">/repos/&lt;owner&gt;/&lt;repo&gt;/dependency-graph/sbom</span>.
                API tokens are configured server-side via secure env/file settings and are never stored in pipeline records.
                Auto-ingestion pipelines are configured from the <span className="mono">Configurations</span> section.
              </div>
            </>
          )}
        </div>

          <div className="button-row form-submit-row">
            <button type="button" className="btn btn-primary" onClick={submit} disabled={loading}>
              {loading ? 'Ingesting...' : 'Ingest SBOM'}
            </button>
          </div>
        </div>
      )}

      {result && <div className="notice">{result}</div>}
      {error && <div className="notice error">{error}</div>}
    </div>
  );
}
