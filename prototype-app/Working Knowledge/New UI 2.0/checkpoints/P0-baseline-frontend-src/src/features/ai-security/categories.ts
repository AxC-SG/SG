export type AiArtifactCategoryKey = 'AGENTS' | 'PROMPTS' | 'TOOLS' | 'COMPONENTS' | 'MODELS' | 'GUARDRAILS' | 'IDENTITY';

export type AiArtifactCategory = {
  key: AiArtifactCategoryKey;
  label: string;
  nativeKinds: string[];
};

/** Cross-provider groupings for native artifact kinds that play the same role on AWS and
 * Azure. Deliberately small and explicit — only kinds with a genuine functional equivalent
 * on the other provider are combined here. Everything else stays as its own native-kind row. */
export const AI_ARTIFACT_CATEGORIES: AiArtifactCategory[] = [
  { key: 'AGENTS', label: 'Agents', nativeKinds: ['AWS_BEDROCK_AGENT', 'AWS_AGENTCORE_RUNTIME', 'AZURE_FOUNDRY_AGENTS', 'AZURE_CLASSIC_FOUNDRY_AGENTS', 'MICROSOFT_COPILOT'] },
  { key: 'PROMPTS', label: 'Prompts', nativeKinds: ['AWS_BEDROCK_PROMPT', 'AZURE_FOUNDRY_PROMPT', 'AZURE_CLASSIC_FOUNDRY_PROMPT', 'MICROSOFT_COPILOT_PROMPT'] },
  { key: 'TOOLS', label: 'Tools', nativeKinds: ['AZURE_FOUNDRY_AGENT_TOOLS', 'AZURE_CLASSIC_FOUNDRY_AGENT_TOOLS', 'MICROSOFT_COPILOT_TOOL'] },
  { key: 'COMPONENTS', label: 'Components', nativeKinds: ['MICROSOFT_COPILOT_COMPONENT'] },
  { key: 'MODELS', label: 'Models', nativeKinds: ['AWS_BEDROCK_MODEL', 'AZURE_FOUNDRY_DEPLOYMENTS', 'AZURE_ML_MODELS'] },
  { key: 'GUARDRAILS', label: 'Guardrails', nativeKinds: ['AWS_BEDROCK_GUARDRAIL', 'AZURE_RAI_POLICIES'] },
  { key: 'IDENTITY', label: 'Identities', nativeKinds: ['AZURE_RBAC_GLOBAL', 'AZURE_IDENTITY', 'AZURE_BOT_IDENTITIES'] },
];

const NATIVE_KIND_TO_CATEGORY = new Map<string, AiArtifactCategory>(
  AI_ARTIFACT_CATEGORIES.flatMap((category) => category.nativeKinds.map((kind) => [kind, category] as const)),
);

export function categoryForNativeKind(nativeKind: string): AiArtifactCategory | undefined {
  return NATIVE_KIND_TO_CATEGORY.get(nativeKind);
}

/** Drops the leading AWS_/AZURE_ provider token from a native-kind label so cross-provider
 * views read as entity types ("Identity") rather than provider-specific names ("Azure Identity"). */
export function stripProviderPrefix(nativeKind: string): string {
  return nativeKind.replace(/^(AWS|AZURE)_/, '').replace(/_/g, ' ');
}

export function combinedNativeKindFilterValue(nativeKinds: string[]): string {
  return nativeKinds.join(',');
}

export const AI_AGENT_VERSION_KINDS = ['AWS_BEDROCK_AGENT_VERSION', 'AWS_AGENTCORE_RUNTIME_VERSION',
  'AZURE_FOUNDRY_AGENT_VERSION', 'AZURE_FOUNDRY_AGENT_VERSIONS', 'AZURE_CLASSIC_FOUNDRY_AGENT_VERSIONS', 'MICROSOFT_COPILOT_VERSION'];

export function isAgentVersionKind(kind: string): boolean {
  return AI_AGENT_VERSION_KINDS.includes(kind);
}

export function legacyAgentRosterRedirect(search: string): string | null {
  const params = new URLSearchParams(search);
  if (params.get('artifactType') !== 'AI_AGENT_VERSION'
      && !['AGENT_VERSIONS', 'agent-versions'].includes(params.get('view') ?? '')
      && !(params.get('nativeKind') ?? '').split(',').some(isAgentVersionKind)) return null;
  const kept = new URLSearchParams();
  for (const key of ['provider', 'subscription']) {
    const value = params.get(key);
    if (value) kept.set(key, value);
  }
  return '/inventory/ai/agents' + (kept.size ? '?' + kept.toString() : '');
}
