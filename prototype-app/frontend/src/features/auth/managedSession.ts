export const managedBrowserAuthEnabled = import.meta.env.VITE_MANAGED_BROWSER_AUTH_ENABLED === 'true';

const WORKSPACE_KEY = 'scout:workspace:v1';
const PLATFORM_SELECTION_KEY = 'scout:platform-workspace:v1';
const RETURN_PATH_KEY = 'scout:sign-in-return:v1';

export function getManagedWorkspace(): string | null {
  return window.sessionStorage.getItem(WORKSPACE_KEY);
}

export function setManagedWorkspace(tenantId: string | null, platformOwner = false) {
  if (tenantId === null) window.sessionStorage.removeItem(WORKSPACE_KEY);
  else window.sessionStorage.setItem(WORKSPACE_KEY, tenantId);
  if (tenantId && platformOwner) window.sessionStorage.setItem(PLATFORM_SELECTION_KEY, tenantId);
  else window.sessionStorage.removeItem(PLATFORM_SELECTION_KEY);
}

export function getManagedPlatformWorkspace(): string | null {
  const workspace = getManagedWorkspace();
  return workspace === window.sessionStorage.getItem(PLATFORM_SELECTION_KEY) ? workspace : null;
}

export function rememberManagedReturnPath(path: string | null) {
  window.sessionStorage.removeItem(RETURN_PATH_KEY);
  if (!path || !path.startsWith('/') || path.startsWith('//') || path.includes('\\')) return;
  const target = new URL(path, window.location.origin);
  if (target.origin !== window.location.origin || target.pathname === '/login') return;
  window.sessionStorage.setItem(RETURN_PATH_KEY, target.pathname + target.search + target.hash);
}

export function getManagedReturnPath(): string | null {
  const path = window.sessionStorage.getItem(RETURN_PATH_KEY);
  return path?.startsWith('/') && !path.startsWith('//') && !path.includes('\\') ? path : null;
}
