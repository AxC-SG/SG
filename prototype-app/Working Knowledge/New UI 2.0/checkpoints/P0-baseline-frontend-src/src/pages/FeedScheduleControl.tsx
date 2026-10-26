import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { intelligenceApi } from '../features/intelligence/api';

export function FeedScheduleControl({ syncType }: { syncType: string }) {
  const client = useQueryClient();
  const schedules = useQuery({ queryKey: ['intelligence-feed-schedules'], queryFn: intelligenceApi.schedules });
  const save = useMutation({ mutationFn: ({ enabled, interval }: { enabled: boolean; interval: number }) => intelligenceApi.saveSchedule(syncType, enabled, interval), onSuccess: () => client.invalidateQueries({ queryKey: ['intelligence-feed-schedules'] }) });
  const schedule = schedules.data?.find((item) => item.sync_type === syncType);
  return <div className="vi-run-every-row">
    {schedule && <><label><input type="checkbox" checked={schedule.enabled} disabled={save.isPending} onChange={(event) => save.mutate({ enabled: event.target.checked, interval: schedule.interval_hours })} /> Scheduled ingestion</label>
      <form key={schedule.interval_hours} onSubmit={(event) => { event.preventDefault(); const hours = Number(new FormData(event.currentTarget).get('interval')); if (Number.isInteger(hours) && hours >= 1 && hours <= 8760) save.mutate({ enabled: schedule.enabled, interval: hours }); }}>
        <label>Interval in hours<input name="interval" type="number" min={1} max={8760} required defaultValue={schedule.interval_hours} disabled={save.isPending} /></label><button type="submit" className="btn btn-secondary" disabled={save.isPending}>Save interval</button>
      </form>
      {schedule.enabled && schedule.next_due_at && <span>Next run: {new Date(schedule.next_due_at).toLocaleString()}</span>}</>}
    {(save.error || schedules.error) && <p role="alert">{(save.error ?? schedules.error)?.message}</p>}
  </div>;
}
