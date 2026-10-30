import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { intelligenceApi } from '../features/intelligence/api';

function formatNextRun(iso: string): string {
  // Name the viewer's time zone so "next run" is not read as server or UTC time.
  return new Date(iso).toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short', timeZoneName: 'short' });
}

export function FeedScheduleControl({ syncType }: { syncType: string }) {
  const client = useQueryClient();
  const intervalId = React.useId();
  const [saved, setSaved] = React.useState('');
  const schedules = useQuery({ queryKey: ['intelligence-feed-schedules'], queryFn: intelligenceApi.schedules });
  const save = useMutation({
    mutationFn: ({ enabled, interval }: { enabled: boolean; interval: number }) => intelligenceApi.saveSchedule(syncType, enabled, interval),
    onMutate: () => setSaved(''),
    onSuccess: (_result, { enabled, interval }) => {
      setSaved(enabled ? `Schedule saved: every ${interval} hour${interval === 1 ? '' : 's'}.` : 'Scheduled ingestion turned off.');
      return client.invalidateQueries({ queryKey: ['intelligence-feed-schedules'] });
    },
  });
  const schedule = schedules.data?.find((item) => item.sync_type === syncType);
  return <div className="vi-run-every-row">
    {schedules.isPending && <span className="muted">Loading schedule…</span>}
    {schedules.data && !schedule && <span className="muted">This feed has no configurable schedule.</span>}
    {schedule && <><label><input type="checkbox" checked={schedule.enabled} disabled={save.isPending} onChange={(event) => save.mutate({ enabled: event.target.checked, interval: schedule.interval_hours })} /> Scheduled ingestion</label>
      <form key={schedule.interval_hours} onSubmit={(event) => { event.preventDefault(); const hours = Number(new FormData(event.currentTarget).get('interval')); if (Number.isInteger(hours) && hours >= 1 && hours <= 8760) save.mutate({ enabled: schedule.enabled, interval: hours }); }}>
        <label htmlFor={intervalId}>Interval in hours</label>
        <input id={intervalId} name="interval" type="number" min={1} max={8760} required defaultValue={schedule.interval_hours} disabled={save.isPending} aria-describedby={`${intervalId}-help`} />
        <span id={`${intervalId}-help`} className="field-hint">Whole hours, 1 to 8760.</span>
        <button type="submit" className="btn btn-secondary" disabled={save.isPending}>{save.isPending ? 'Saving…' : 'Save interval'}</button>
      </form>
      {schedule.enabled && schedule.next_due_at && <span>Next run: {formatNextRun(schedule.next_due_at)}</span>}
      {!schedule.enabled && <span className="muted">Runs only when started manually.</span>}</>}
    {saved && !save.error && <p role="status">{saved}</p>}
    {(save.error || schedules.error) && <p role="alert">{(save.error ?? schedules.error)?.message}</p>}
  </div>;
}
