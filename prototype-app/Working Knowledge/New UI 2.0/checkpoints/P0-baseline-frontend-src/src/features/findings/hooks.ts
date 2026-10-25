import React from 'react';
import type { SetURLSearchParams } from 'react-router-dom';
import type { ActiveFindingsQueryContext, FindingQueueDefinition, FindingsFilterModel } from './types';

type UseFindingsQueryContextOptions = {
  searchParams: URLSearchParams;
  setSearchParams: SetURLSearchParams;
  availableQueues: FindingQueueDefinition[];
  adHocFilterModel: FindingsFilterModel;
};

export function useFindingsQueryContext({
  searchParams,
  setSearchParams,
  availableQueues,
  adHocFilterModel,
}: UseFindingsQueryContextOptions) {
  const explicitQueueKey = searchParams.get('queue')?.trim() || null;
  const initialQueueKey = explicitQueueKey || 'all-findings';
  const resolvedDefaultRef = React.useRef(false);
  const [activeQueueKey, setActiveQueueKey] = React.useState(initialQueueKey);

  const personalQueues = React.useMemo(() => availableQueues.filter((queue) => queue.kind === 'PERSONAL'), [availableQueues]);
  const activeQueue = React.useMemo(
    () => availableQueues.find((queue) => queue.key === activeQueueKey) ?? availableQueues[0] ?? null,
    [availableQueues, activeQueueKey]
  );
  const defaultQueue = React.useMemo(
    () => availableQueues.find((queue) => queue.isDefault) ?? null,
    [availableQueues]
  );

  React.useEffect(() => {
    if (availableQueues.length === 0) return;
    if (!resolvedDefaultRef.current && explicitQueueKey == null) {
      resolvedDefaultRef.current = true;
      if (defaultQueue && defaultQueue.key !== activeQueueKey) {
        setActiveQueueKey(defaultQueue.key);
        return;
      }
    }
    if (availableQueues.some((queue) => queue.key === activeQueueKey)) return;
    setActiveQueueKey(availableQueues[0]!.key);
  }, [availableQueues, activeQueueKey, defaultQueue, explicitQueueKey]);

  React.useEffect(() => {
    const next = new URLSearchParams(searchParams);
    if (activeQueueKey === 'all-findings') next.delete('queue');
    else next.set('queue', activeQueueKey);
    if (next.toString() === searchParams.toString()) return;
    setSearchParams(next, { replace: true });
  }, [activeQueueKey, searchParams, setSearchParams]);

  const activeQueryContext = React.useMemo<ActiveFindingsQueryContext>(() => ({
    queueKey: activeQueue?.key ?? activeQueueKey,
    title: activeQueue?.title ?? 'All Findings',
    queueKind: activeQueue?.kind ?? 'BUILT_IN',
    editable: activeQueue?.editable ?? false,
    baseFilter: activeQueue?.filter ?? {},
    adHocFilters: adHocFilterModel,
    healthScopeLabel: `Queue health for ${activeQueue?.title ?? 'All Findings'}`,
  }), [activeQueue, activeQueueKey, adHocFilterModel]);

  return {
    explicitQueueKey,
    activeQueueKey,
    setActiveQueueKey,
    personalQueues,
    activeQueue,
    defaultQueue,
    activeQueryContext,
  };
}

export function useFindingsCursorPaging(queueKey: string, adHocFilterModel: FindingsFilterModel, pageSize: number) {
  const [page, setPage] = React.useState(0);
  const [pageCursors, setPageCursors] = React.useState<Array<string | null>>([null]);

  React.useEffect(() => {
    setPage(0);
    setPageCursors([null]);
  }, [queueKey, adHocFilterModel]);

  const effectiveServerFilterModel = React.useMemo<FindingsFilterModel>(() => ({
    ...adHocFilterModel,
    queueKey,
    cursor: pageCursors[page] ?? undefined,
    limit: pageSize,
  }), [adHocFilterModel, queueKey, page, pageCursors, pageSize]);

  return {
    page,
    setPage,
    pageCursors,
    setPageCursors,
    effectiveServerFilterModel,
  };
}
