export const staticAuthenticationVariables = [
  'VITE_API_KEY', 'VITE_CREATOR_KEY', 'VITE_AUTH_TOKEN', 'VITE_USER_ID', 'VITE_TENANT_ID',
];

export function rejectProductionAuthenticationInputs(environment) {
  const configured = staticAuthenticationVariables.filter((name) => environment[name]?.trim());
  if (configured.length > 0) {
    // Names only: errors and CI logs must never echo their values.
    throw new Error(`Static authentication inputs are development-only: ${configured.join(', ')}`);
  }
}
