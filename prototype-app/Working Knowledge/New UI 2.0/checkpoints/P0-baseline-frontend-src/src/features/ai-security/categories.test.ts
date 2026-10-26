import { describe, expect, it } from 'vitest';
import { categoryForNativeKind, combinedNativeKindFilterValue, stripProviderPrefix, legacyAgentRosterRedirect, isAgentVersionKind } from './categories';

describe('categoryForNativeKind', () => {
  it('maps AWS and Azure agent kinds to the same Agents category', () => {
    expect(categoryForNativeKind('AWS_BEDROCK_AGENT')?.key).toBe('AGENTS');
    expect(categoryForNativeKind('AWS_AGENTCORE_RUNTIME')?.key).toBe('AGENTS');
    expect(categoryForNativeKind('AZURE_BOT_SERVICES')).toBeUndefined();
  });

  it('maps AWS and Azure guardrail kinds to the same Guardrails category', () => {
    expect(categoryForNativeKind('AWS_BEDROCK_GUARDRAIL')?.key).toBe('GUARDRAILS');
    expect(categoryForNativeKind('AZURE_RAI_POLICIES')?.key).toBe('GUARDRAILS');
  });

  it('groups Azure RBAC and Identity under Identity', () => {
    expect(categoryForNativeKind('AZURE_RBAC_GLOBAL')?.key).toBe('IDENTITY');
    expect(categoryForNativeKind('AZURE_IDENTITY')?.key).toBe('IDENTITY');
    expect(categoryForNativeKind('AZURE_BOT_IDENTITIES')?.key).toBe('IDENTITY');
  });

  it('returns undefined for kinds with no cross-provider grouping', () => {
    expect(categoryForNativeKind('AWS_BEDROCK_INFERENCE_PROFILE')).toBeUndefined();
    expect(categoryForNativeKind('AZURE_BOT_CHANNELS')).toBeUndefined();
  });
});

describe('stripProviderPrefix', () => {
  it('drops the leading provider token and humanizes the rest', () => {
    expect(stripProviderPrefix('AWS_BEDROCK_INFERENCE_PROFILE')).toBe('BEDROCK INFERENCE PROFILE');
    expect(stripProviderPrefix('AZURE_IDENTITY')).toBe('IDENTITY');
    expect(stripProviderPrefix('AZURE_AI_ACCOUNTS')).toBe('AI ACCOUNTS');
  });
});

describe('combinedNativeKindFilterValue', () => {
  it('joins native kinds into a single comma-separated filter value', () => {
    expect(combinedNativeKindFilterValue(['AWS_BEDROCK_AGENT', 'AZURE_BOT_SERVICES'])).toBe('AWS_BEDROCK_AGENT,AZURE_BOT_SERVICES');
  });
});

describe('legacy agent version links', () => {
  it('preserves only provider and subscription for every version kind', () => {
    for (const kind of ['AWS_BEDROCK_AGENT_VERSION', 'AWS_AGENTCORE_RUNTIME_VERSION', 'AZURE_FOUNDRY_AGENT_VERSIONS', 'MICROSOFT_COPILOT_VERSION']) {
      expect(isAgentVersionKind(kind)).toBe(true);
      expect(legacyAgentRosterRedirect(`?nativeKind=${kind}&provider=AWS&subscription=acct&severity=HIGH&page=4&artifactType=AI_COMPONENT&view=others`))
        .toBe('/inventory/ai/agents?provider=AWS&subscription=acct');
    }
  });
  it('redirects artifact-type and category links while preserving direct detail routing', () => {
    expect(legacyAgentRosterRedirect('?artifactType=AI_AGENT_VERSION')).toBe('/inventory/ai/agents');
    expect(legacyAgentRosterRedirect('?view=agent-versions')).toBe('/inventory/ai/agents');
    expect(legacyAgentRosterRedirect('?nativeKind=AZURE_BOT_SERVICES')).toBeNull();
  });
});
