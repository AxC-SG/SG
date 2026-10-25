import { screen, within } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { api } from '../api/client';
import { renderWithProviders } from '../test/test-utils';
import { InventoryRunQueuePage } from './InventoryRunQueuePage';

describe('InventoryRunQueuePage', () => {
  afterEach(() => vi.restoreAllMocks());

  it('shows AWS, Azure, and Copilot AI discovery progress with provider details and errors', async () => {
    vi.spyOn(api, 'listIngestionJobs').mockResolvedValue({
      items: [{
        jobId: 'copilot-job', jobType: 'AI_SECURITY_COPILOT_STUDIO', status: 'QUEUED',
        sourceType: 'ai-security-copilot', assetIdentifier: 'connector:copilot-connector',
        requestedAt: '2026-07-29T09:10:00Z', requestedBy: 'operator', attemptCount: 0,
        resultJson: null, failureCode: null, failureMessage: null, sbomUploadId: null, startedAt: null, completedAt: null,
      }], page: 0, size: 100, totalItems: 1, totalPages: 1
    });
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([
      {
        id: 'aws-run',
        syncType: 'AI_SECURITY_AWS_BEDROCK',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'running',
        queuePosition: 1,
        recordsFetched: 8,
        recordsInserted: 8,
        recordsUpdated: 0,
        recordsFailed: 0,
        startedAt: '2026-07-29T09:00:00Z',
        metadataJson: JSON.stringify({
          provider: 'AWS',
          connectorId: 'aws-connector',
          accountId: '123456789012',
          regions: ['us-east-1', 'us-west-2'],
        }),
      },
      {
        id: 'azure-run',
        syncType: 'AI_SECURITY_AZURE_DISCOVERY',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'failed',
        recordsFetched: 3,
        recordsInserted: 3,
        recordsUpdated: 0,
        recordsFailed: 1,
        startedAt: '2026-07-29T08:00:00Z',
        completedAt: '2026-07-29T08:00:15Z',
        errorMessage: 'Azure AI Security discovery failed',
        metadataJson: JSON.stringify({
          provider: 'AZURE',
          connectorId: 'azure-connector',
          subscriptionId: 'sub-1',
          families: ['AZURE_AI_ACCOUNTS'],
        }),
      },
      {
        id: 'azure-cloud-run',
        syncType: 'AZURE_DISCOVERY',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'queued',
        queuePosition: 2,
        recordsFetched: 0,
        recordsInserted: 0,
        recordsUpdated: 0,
        recordsFailed: 0,
        startedAt: '2026-07-29T09:05:00Z',
        metadataJson: JSON.stringify({
          sourceSystem: 'azure',
          azureTenantId: 'tenant-1',
          subscriptionIds: ['sub-1'],
          regions: ['eastus'],
        }),
      },
      {
        id: 'aws-cloud-run',
        syncType: 'AWS_DISCOVERY',
        runDomain: 'INVENTORY',
        runClass: 'INGESTION',
        status: 'queued',
        queuePosition: 3,
        recordsFetched: 0,
        recordsInserted: 0,
        recordsUpdated: 0,
        recordsFailed: 0,
        startedAt: '2026-07-29T09:06:00Z',
        metadataJson: JSON.stringify({
          sourceSystem: 'aws',
          awsAccountId: '123456789012',
          regions: ['us-east-1'],
          resourceTypes: ['EC2', 'SSM'],
        }),
      },
    ]);

    renderWithProviders(<InventoryRunQueuePage />);

    const awsType = await screen.findByText('AWS AI Discovery');
    expect(awsType.closest('a')).toHaveAttribute('href', '/inventory/ai');
    const awsRow = awsType.closest('tr');
    expect(awsRow).not.toBeNull();
    expect(within(awsRow as HTMLTableRowElement).getByText('Running')).toBeInTheDocument();
    expect(within(awsRow as HTMLTableRowElement).getByText('Running now')).toBeInTheDocument();
    expect(within(awsRow as HTMLTableRowElement).getByText('8')).toBeInTheDocument();

    const azureType = screen.getByText('Azure AI Discovery');
    const azureRow = azureType.closest('tr');
    expect(azureRow).not.toBeNull();
    expect(within(azureRow as HTMLTableRowElement).getByText('Failed')).toBeInTheDocument();

    within(azureRow as HTMLTableRowElement).getByText('Details').click();
    expect(within(azureRow as HTMLTableRowElement).getByText(/Provider: AZURE/)).toBeInTheDocument();
    expect(within(azureRow as HTMLTableRowElement).getByText(/Azure subscription: sub-1/)).toBeInTheDocument();
    expect(within(azureRow as HTMLTableRowElement).getByText(
      /Error: Azure AI Security discovery failed/
    )).toBeInTheDocument();

    const copilotType = screen.getByText('Microsoft Copilot Discovery');
    const copilotRow = copilotType.closest('tr');
    expect(copilotRow).not.toBeNull();
    expect(within(copilotRow as HTMLTableRowElement).getByText('Queued')).toBeInTheDocument();
    within(copilotRow as HTMLTableRowElement).getByText('Details').click();
    expect(within(copilotRow as HTMLTableRowElement).getByText(/Provider: MICROSOFT_COPILOT/)).toBeInTheDocument();
    expect(within(copilotRow as HTMLTableRowElement).getByText(
      /Waiting for the AI Security discovery worker to claim this job/
    )).toBeInTheDocument();

    const azureCloudType = screen.getByText('Azure Cloud Discovery');
    const azureCloudRow = azureCloudType.closest('tr');
    expect(azureCloudRow).not.toBeNull();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText('Queued')).toBeInTheDocument();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText('#2')).toBeInTheDocument();
    within(azureCloudRow as HTMLTableRowElement).getByText('Details').click();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText(
      /Azure subscriptions: sub-1/
    )).toBeInTheDocument();
    expect(within(azureCloudRow as HTMLTableRowElement).getByText(/Regions: eastus/)).toBeInTheDocument();

    const awsCloudType = screen.getByText('AWS Cloud Discovery');
    const awsCloudRow = awsCloudType.closest('tr');
    expect(awsCloudRow).not.toBeNull();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText('Queued')).toBeInTheDocument();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText('#3')).toBeInTheDocument();
    within(awsCloudRow as HTMLTableRowElement).getByText('Details').click();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText(
      /AWS account: 123456789012/
    )).toBeInTheDocument();
    expect(within(awsCloudRow as HTMLTableRowElement).getByText(
      /Resource types: EC2, SSM/
    )).toBeInTheDocument();
  });

  it('shows queued Azure AI discovery jobs before a worker creates the sync run', async () => {
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([]);
    vi.spyOn(api, 'listIngestionJobs').mockResolvedValue({
      items: [{
        jobId: 'azure-job',
        jobType: 'AI_SECURITY_AZURE_DISCOVERY',
        sourceType: 'ai-security-azure',
        assetIdentifier: 'ai-security-azure:azure-connector',
        status: 'QUEUED',
        requestedBy: 'analyst',
        requestedAt: '2026-09-13T10:00:00Z',
        startedAt: null,
        completedAt: null,
        attemptCount: 0,
        failureCode: null,
        failureMessage: null,
        sbomUploadId: null,
        resultJson: null,
      }],
      page: 0,
      size: 100,
      totalItems: 1,
      totalPages: 1,
    });

    renderWithProviders(<InventoryRunQueuePage />);

    const type = await screen.findByText('Azure AI Discovery');
    const row = type.closest('tr');
    expect(row).not.toBeNull();
    expect(within(row as HTMLTableRowElement).getByText('Queued')).toBeInTheDocument();
    within(row as HTMLTableRowElement).getByText('Details').click();
    expect(within(row as HTMLTableRowElement).getByText(
      /Waiting for the AI Security discovery worker to claim this job/
    )).toBeInTheDocument();
  });

  it('keeps claimed Azure jobs visible and includes completed Copilot discovery runs', async () => {
    vi.spyOn(api, 'listSyncRuns').mockResolvedValue([{
      id: 'copilot-run',
      syncType: 'AI_SECURITY_COPILOT_STUDIO',
      runDomain: 'INVENTORY',
      runClass: 'INGESTION',
      status: 'completed',
      recordsFetched: 6,
      recordsInserted: 6,
      recordsUpdated: 0,
      recordsFailed: 0,
      startedAt: '2026-09-13T09:00:00Z',
      completedAt: '2026-09-13T09:00:04Z',
      metadataJson: JSON.stringify({ provider: 'MICROSOFT_COPILOT', connectorId: 'copilot-connector' }),
    }]);
    vi.spyOn(api, 'listIngestionJobs').mockResolvedValue({
      items: [{
        jobId: 'azure-running-job',
        jobType: 'AI_SECURITY_AZURE_DISCOVERY',
        sourceType: 'ai-security-azure',
        assetIdentifier: 'ai-security-azure:azure-connector',
        status: 'RUNNING',
        requestedBy: 'analyst',
        requestedAt: '2026-09-13T10:00:00Z',
        startedAt: '2026-09-13T10:00:01Z',
        completedAt: null,
        attemptCount: 1,
        failureCode: null,
        failureMessage: null,
        sbomUploadId: null,
        resultJson: null,
      }],
      page: 0,
      size: 100,
      totalItems: 1,
      totalPages: 1,
    });

    renderWithProviders(<InventoryRunQueuePage />);

    const azureType = await screen.findByText('Azure AI Discovery');
    const azureRow = azureType.closest('tr') as HTMLTableRowElement;
    expect(within(azureRow).getByText('Running')).toBeInTheDocument();
    within(azureRow).getByText('Details').click();
    expect(within(azureRow).getByText(/worker is starting this run/)).toBeInTheDocument();

    const copilotType = screen.getByText('Microsoft Copilot Discovery');
    const copilotRow = copilotType.closest('tr') as HTMLTableRowElement;
    expect(within(copilotRow).getByText('Completed')).toBeInTheDocument();
    expect(within(copilotRow).getByText('6')).toBeInTheDocument();
  });
});
