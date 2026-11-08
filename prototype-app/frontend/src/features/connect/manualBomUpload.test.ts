import { webcrypto } from 'node:crypto';
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';
import { api, ApiError } from '../../api/client';
import { submitBomFile } from './manualBomUpload';

const metadata = {
  bomType: 'SBOM',
  assetType: 'APPLICATION',
  assetName: 'Checkout',
  assetIdentifier: 'checkout'
} as const;
const scope = { tenantId: 'tenant-1', userId: 'user-1' };
const upload = { uploadId: 'upload-1', status: 'PENDING', expiresAt: '2026-11-08T10:00:00Z', jobId: null };
const ticket = {
  upload,
  uploadUrl: 'https://bucket.example.test/bom?signature=private',
  uploadHeaders: { 'if-none-match': '*' }
};

describe('submitBomFile', () => {
  beforeEach(() => {
    vi.stubGlobal('crypto', webcrypto);
    window.sessionStorage.clear();
  });

  afterEach(() => {
    vi.restoreAllMocks();
    vi.unstubAllGlobals();
    window.sessionStorage.clear();
  });

  it('reuses the intent after an interrupted transfer and finalizes an already stored object', async () => {
    const file = new File(['abc'], 'checkout.json');
    const create = vi.spyOn(api, 'createBomUpload').mockResolvedValue(ticket);
    const complete = vi.spyOn(api, 'completeBomUpload').mockResolvedValue({ ...upload, status: 'QUEUED', jobId: 'job-1' });
    const put = vi.fn()
      .mockRejectedValueOnce(new TypeError('Network error'))
      .mockResolvedValueOnce(new Response(null, { status: 412 }));
    vi.stubGlobal('fetch', put);
    const onStatus = vi.fn();

    await expect(submitBomFile(file, metadata, scope, onStatus)).rejects.toThrow('transfer was interrupted');
    expect(complete).not.toHaveBeenCalled();
    await expect(submitBomFile(file, metadata, scope, onStatus)).resolves.toBe('job-1');
    expect(create.mock.calls[0]).toEqual(create.mock.calls[1]);
    expect(create.mock.calls[0][0]).toMatchObject({
      sha256: 'ungWv48Bz+pBQUDeXa4iI7ADYaOWF3qctBD/YfIAFa0=',
      filename: file.name,
      size: file.size
    });
    expect(put).toHaveBeenLastCalledWith(ticket.uploadUrl, expect.objectContaining({
      body: file,
      headers: ticket.uploadHeaders,
      method: 'PUT',
      credentials: 'omit'
    }));
    expect(complete).toHaveBeenCalledOnce();
    expect(window.sessionStorage.length).toBe(0);
  });

  it('rotates an expired intent and skips storage when acceptance is already recorded', async () => {
    const file = new File(['abc'], 'checkout.json');
    const create = vi.spyOn(api, 'createBomUpload')
      .mockRejectedValueOnce(new ApiError('Expired', 410))
      .mockResolvedValueOnce({ upload: { ...upload, jobId: 'job-1' }, uploadUrl: null, uploadHeaders: {} });
    const put = vi.fn();
    vi.stubGlobal('fetch', put);

    await expect(submitBomFile(file, metadata, scope, vi.fn())).rejects.toThrow('upload expired');
    await expect(submitBomFile(file, metadata, scope, vi.fn())).resolves.toBe('job-1');
    expect(create.mock.calls[0][1]).not.toBe(create.mock.calls[1][1]);
    expect(put).not.toHaveBeenCalled();
  });
});
