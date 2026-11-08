import { api, ApiError, getStoredAuthToken, type BomUploadMetadata } from '../../api/client';
import { getManagedWorkspace, managedBrowserAuthEnabled } from '../auth/managedSession';

export const durableBomUploadsEnabled = import.meta.env.VITE_DURABLE_BOM_UPLOADS_ENABLED === 'true';
export const maxBomUploadBytes = 50 * 1024 * 1024;

async function sha256Base64(bytes: ArrayBuffer) {
  const digest = new Uint8Array(await crypto.subtle.digest('SHA-256', bytes));
  return btoa(String.fromCharCode(...digest));
}

export async function submitBomFile(
  file: File,
  metadata: BomUploadMetadata,
  scope: { tenantId: string; userId: string },
  onStatus: (message: string) => void
): Promise<string> {
  if (file.size === 0 || file.size > maxBomUploadBytes) {
    throw new Error('Choose a BOM file between 1 byte and 50 MiB.');
  }
  const originalToken = managedBrowserAuthEnabled ? '' : getStoredAuthToken();
  const verifySession = () => {
    const scopeChanged = managedBrowserAuthEnabled
      ? scope.tenantId !== getManagedWorkspace()
      : originalToken !== getStoredAuthToken();
    if (scopeChanged) {
      throw new Error('Workspace access changed. Return to the original workspace to retry this import.');
    }
  };
  onStatus('Preparing file for upload…');
  const payload = {
    ...metadata,
    filename: file.name,
    size: file.size,
    sha256: await sha256Base64(await file.arrayBuffer())
  };
  const fingerprint = await sha256Base64(new TextEncoder().encode(JSON.stringify([scope, payload])).buffer);
  const storageKey = `scout:bom-upload:v1:${fingerprint}`;
  const key = window.sessionStorage.getItem(storageKey) ?? crypto.randomUUID();
  window.sessionStorage.setItem(storageKey, key);

  try {
    verifySession();
    const ticket = await api.createBomUpload(payload, key);
    let jobId = ticket.upload.jobId;
    if (!jobId) {
      if (!ticket.uploadUrl || new URL(ticket.uploadUrl).protocol !== 'https:') {
        throw new Error('The server did not provide a secure upload URL.');
      }
      onStatus('Uploading BOM. Keep this tab open until the import is accepted.');
      let response: Response;
      try {
        response = await fetch(ticket.uploadUrl, {
          method: 'PUT',
          body: file,
          headers: ticket.uploadHeaders,
          credentials: 'omit',
          redirect: 'error',
          referrerPolicy: 'no-referrer'
        });
      } catch {
        throw new Error('The file transfer was interrupted. Retry with the same file and details.');
      }
      // A prior transfer may have completed before the browser received its response.
      // Only the API can verify the existing object and accept it for processing.
      if (!response.ok && response.status !== 412) {
        throw new Error('The file could not be uploaded. Retry with the same file and details.');
      }
      verifySession();
      onStatus('Verifying the uploaded file…');
      jobId = (await api.completeBomUpload(ticket.upload.uploadId)).jobId;
    }
    if (!jobId) throw new Error('The import was not accepted. Retry with the same file and details.');
    window.sessionStorage.removeItem(storageKey);
    return jobId;
  } catch (error) {
    if (error instanceof ApiError && error.status === 410) {
      window.sessionStorage.removeItem(storageKey);
      throw new Error('The upload expired. Submit the file again to start a new import.');
    }
    throw error;
  }
}
