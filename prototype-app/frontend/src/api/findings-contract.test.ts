import { afterEach, describe, expect, it, vi } from 'vitest';
import { api, clearStoredAuthToken } from './client';
import type { FindingQueueUpsertRequest } from '../features/findings/types';

function mockResponse() {
  return vi.spyOn(globalThis, 'fetch').mockImplementation(async () => new Response('{}', {
    status: 200, headers: { 'content-type': 'application/json' },
  }));
}

function requestUrl(input: RequestInfo | URL) {
  return new URL(String(input), 'http://localhost');
}

afterEach(() => {
  vi.restoreAllMocks();
  clearStoredAuthToken();
});

describe('Findings HTTP behavior contract', () => {
  it('preserves multi-column selections and opaque cursor values in the table request', async () => {
    const fetchSpy = mockResponse();
    const cursor = 'cursor+/=&next:25';
    await api.listFindings({
      queueKey: ' personal:production ', severity: ['CRITICAL', 'HIGH'], status: ['OPEN', 'RESOLVED'],
      creationSource: ['MANUAL', 'AUTOMATIC'], assetType: ['HOST', 'CONTAINER_IMAGE'],
      assetName: ' prod/payments & gateway ', packageName: ' @scope/runtime+client ',
      supportGroup: ' Platform / EU ', assignedTo: ' analyst@example.test ',
      unassignedOnly: false, incidentLinked: true, dueDateBand: 'overdue',
      cursor: ` ${cursor} `, limit: 25,
    });
    const url = requestUrl(fetchSpy.mock.calls[0][0]);
    expect(url.pathname).toBe('/api/findings');
    const params = url.searchParams;
    expect(params.getAll('severity')).toEqual(['CRITICAL', 'HIGH']);
    expect(params.getAll('status')).toEqual(['OPEN', 'RESOLVED']);
    expect(params.getAll('creationSource')).toEqual(['MANUAL', 'AUTOMATIC']);
    expect(params.getAll('assetType')).toEqual(['HOST', 'CONTAINER_IMAGE']);
    expect(Object.fromEntries(params)).toMatchObject({
      queueKey: 'personal:production', assetName: 'prod/payments & gateway', packageName: '@scope/runtime+client',
      supportGroup: 'Platform / EU', assignedTo: 'analyst@example.test', unassignedOnly: 'false',
      incidentLinked: 'true', dueDateBand: 'overdue', cursor, limit: '25',
    });
  });

  it.each(['OPEN', 'RESOLVED', undefined])('retains both AI software constraints for status %s', async (status) => {
    const fetchSpy = mockResponse();
    await api.listFindings({
      findingKind: ['VULNERABILITY'], hasAffectedAiResource: true,
      status: status ? [status] : undefined, size: 100,
    });
    const params = requestUrl(fetchSpy.mock.calls[0][0]).searchParams;
    expect(params.getAll('findingKind')).toEqual(['VULNERABILITY']);
    expect(params.get('hasAffectedAiResource')).toBe('true');
    expect(params.getAll('status')).toEqual(status ? [status] : []);
    expect(params.get('size')).toBe('100');
  });

  // Page tests verify which scope each hook receives. This checks that the HTTP layer
  // carries that scope without retaining table drilldowns from an earlier request.
  it('keeps queue aggregate requests independent of table drilldowns and cursor paging', async () => {
    const fetchSpy = mockResponse();
    const queueScope = { queueKey: 'personal:production', status: ['OPEN'] };
    await api.listFindings({ ...queueScope, severity: ['HIGH'], assetName: 'payments', cursor: 'next-page', limit: 25 });
    await api.getFindingSummary(queueScope);
    await api.getFindingDistributions(queueScope);
    await api.getFindingBacklogHealth(queueScope);
    await api.getFindingGroups('supportGroup', queueScope);
    const urls = fetchSpy.mock.calls.slice(1).map(([input]) => requestUrl(input));
    expect(urls.map(url => url.pathname)).toEqual([
      '/api/findings/summary', '/api/findings/distributions', '/api/findings/backlog-health', '/api/findings/groups',
    ]);
    for (const url of urls) {
      expect(url.searchParams.get('queueKey')).toBe('personal:production');
      expect(url.searchParams.getAll('status')).toEqual(['OPEN']);
      for (const field of ['severity', 'assetName', 'cursor', 'limit']) expect(url.searchParams.has(field)).toBe(false);
    }
    expect(urls[3].searchParams.get('field')).toBe('supportGroup');
    expect(queueScope).toEqual({ queueKey: 'personal:production', status: ['OPEN'] });
  });

  it('sends saved-view scope and metadata unchanged on create and update', async () => {
    const fetchSpy = mockResponse();
    const payload: FindingQueueUpsertRequest = {
      title: 'Production / priority', description: 'Keep selected scope', sourceQueueKey: 'all-findings',
      displayOrder: 0, setAsDefault: false,
      filter: { severity: ['CRITICAL', 'HIGH'], status: ['OPEN'], creationSource: ['MANUAL', 'AUTOMATIC'],
        supportGroup: 'Platform / EU', unassignedOnly: false, incidentLinked: true, dueDateBand: 'due-soon' },
    };
    await api.createFindingQueue(payload);
    await api.updateFindingQueue('personal:priority/eu', payload);
    expect(requestUrl(fetchSpy.mock.calls[0][0]).pathname).toBe('/api/findings/queues');
    expect(requestUrl(fetchSpy.mock.calls[1][0]).pathname).toBe('/api/findings/queues/personal%3Apriority%2Feu');
    expect(fetchSpy.mock.calls.map(([, init]) => init?.method)).toEqual(['POST', 'PUT']);
    for (const [, init] of fetchSpy.mock.calls) expect(JSON.parse(String(init?.body))).toEqual(payload);
  });
});
