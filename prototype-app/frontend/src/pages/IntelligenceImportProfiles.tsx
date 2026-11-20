import React from 'react';
import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { intelligenceApi, type ImportProfile } from '../features/intelligence/api';

const sources = ['NVD'];
function ProfileSchedule({ profile }: { profile: ImportProfile }) {
  const client = useQueryClient();
  const [expanded, setExpanded] = React.useState(false);
  const [draft, setDraft] = React.useState<{ enabled: boolean; intervalHours: string } | null>(null);
  const saved = useQuery({ queryKey: ['intelligence-profile-schedule', profile.id], queryFn: () => intelligenceApi.profileSchedule(profile.id), enabled: expanded });
  const enabled = draft?.enabled ?? saved.data?.enabled;
  const intervalHours = draft?.intervalHours ?? (saved.data ? String(saved.data.intervalHours) : '');
  const hours = Number(intervalHours);
  const supported = profile.sources.length === 1 && profile.sources[0] === 'NVD';
  const schedule = useMutation({
    mutationFn: () => intelligenceApi.scheduleProfile(profile.id, enabled!, hours),
    onSuccess: async () => {
      await client.invalidateQueries({ queryKey: ['intelligence-profile-schedule', profile.id] });
      setDraft(null);
    },
  });
  return <details onToggle={event => setExpanded(event.currentTarget.open)}><summary>Schedule {profile.name}</summary>{expanded && <>
    {saved.isLoading && <p role="status">Loading saved schedule…</p>}
    {saved.error && <p role="alert">Saved schedule could not be loaded: {String(saved.error)} <button type="button" onClick={() => void saved.refetch()}>Retry schedule</button></p>}
    {saved.data && !saved.error && <form aria-label={`Schedule ${profile.name}`} onSubmit={event => { event.preventDefault(); if (supported && enabled !== undefined && Number.isInteger(hours) && hours >= 1 && hours <= 8760) schedule.mutate(); }}>
    <label><input type="checkbox" checked={enabled} disabled={!supported || schedule.isPending} onChange={event => { setDraft({ enabled: event.target.checked, intervalHours }); schedule.reset(); }} />Enable scheduled profile import for {profile.name}</label>
    <label>Interval in hours for {profile.name}<input type="number" min={1} max={8760} step={1} required value={intervalHours} disabled={!supported || schedule.isPending} onChange={event => { setDraft({ enabled: enabled!, intervalHours: event.target.value }); schedule.reset(); }} /></label>
    <button type="submit" className="btn btn-secondary" disabled={!supported || schedule.isPending || !Number.isInteger(hours) || hours < 1 || hours > 8760}>{schedule.isPending ? 'Saving schedule…' : 'Save profile schedule'}</button>
    {!supported && <p role="alert">Scheduled profile imports currently support NVD only.</p>}
    {schedule.error && <p role="alert">Schedule could not be saved: {String(schedule.error)}</p>}
    {schedule.isSuccess && <p role="status">Profile schedule saved.</p>}
    </form>}
  </>}</details>;
}
export function IntelligenceImportProfiles() {
  const client = useQueryClient();
  const [profile, setProfile] = React.useState<Omit<ImportProfile, 'id'>>({ name: '', sources: [], publicationYearFrom: null, publicationYearTo: null, minCvss: null, maxCvss: null, severities: [], includeUnknownScores: true });
  const profiles = useQuery({ queryKey: ['intelligence-import-profiles'], queryFn: intelligenceApi.profiles });
  const save = useMutation({ mutationFn: () => intelligenceApi.saveProfile(profile), onSuccess: () => client.invalidateQueries({ queryKey: ['intelligence-import-profiles'] }) });
  const run = useMutation({ mutationFn: intelligenceApi.runProfile });
  const invalid = !profile.name.trim() || !profile.sources.length || (profile.publicationYearFrom !== null && profile.publicationYearTo !== null && profile.publicationYearFrom > profile.publicationYearTo) || (profile.minCvss !== null && profile.maxCvss !== null && profile.minCvss > profile.maxCvss);
  return <section aria-label="Import profiles"><h3>Import profiles</h3>
    <p>Years refer to source publication dates, not the year in a CVE identifier. Score and severity filters select source records. Provider support determines whether filtering occurs before or after download. Filtered imports do not establish complete historical coverage.</p>
    <p>Scoped profile imports currently support NVD only. Publication years must be between 1970 and 9998.</p>
    {[profiles.error, save.error, run.error].filter(Boolean).map((error, index) => <p role="alert" key={index}>{String(error)}</p>)}
    <form onSubmit={event => { event.preventDefault(); if (!invalid) save.mutate(); }}>
      <label>Profile name<input required value={profile.name} onChange={event => setProfile({ ...profile, name: event.target.value })} /></label>
      <fieldset><legend>Sources</legend>{sources.map(source => <label key={source}><input type="checkbox" checked={profile.sources.includes(source)} onChange={event => setProfile({ ...profile, sources: event.target.checked ? [...profile.sources, source] : profile.sources.filter(item => item !== source) })} />{source} </label>)}</fieldset>
{(['publicationYearFrom', 'publicationYearTo', 'minCvss', 'maxCvss'] as const).map(key => <label key={key}>{{ publicationYearFrom: 'Publication year from', publicationYearTo: 'Publication year to', minCvss: 'Minimum CVSS', maxCvss: 'Maximum CVSS' }[key]}<input type="number" min={key.startsWith('publication') ? 1970 : 0} max={key.startsWith('publication') ? 9998 : 10} step={key.startsWith('publication') ? 1 : 0.1} value={profile[key] ?? ''} onChange={event => setProfile({ ...profile, [key]: event.target.value === '' ? null : Number(event.target.value) })} /></label>)}
      <fieldset><legend>Severities (none selected means all)</legend>{['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'UNKNOWN'].map(severity => <label key={severity}><input type="checkbox" checked={profile.severities.includes(severity)} onChange={event => setProfile({ ...profile, severities: event.target.checked ? [...profile.severities, severity] : profile.severities.filter(item => item !== severity) })} />{severity} </label>)}</fieldset>
      <label><input type="checkbox" checked={profile.includeUnknownScores} onChange={event => setProfile({ ...profile, includeUnknownScores: event.target.checked })} />Include records with unknown scores</label>
      <button type="submit" className="btn btn-primary" disabled={invalid || save.isPending}>Save import profile</button>
    </form>
    {save.isSuccess && <p role="status">Import profile saved.</p>}{run.isSuccess && <p role="status">Import requested. Follow progress in Run History. Manual imports require publication review.</p>}
    {profiles.isLoading && <p>Loading import profiles…</p>}
    {(profiles.data ?? []).map(item => <article key={item.id}><h4>{item.name}</h4><p>Sources: {item.sources.join(', ')} · Publication years: {item.publicationYearFrom ?? 'Any'}–{item.publicationYearTo ?? 'Any'} · CVSS: {item.minCvss ?? 'Any'}–{item.maxCvss ?? 'Any'} · Severity: {item.severities.join(', ') || 'All'} · Unknown scores: {item.includeUnknownScores ? 'Included' : 'Excluded'}</p><button type="button" className="btn btn-secondary" disabled={run.isPending || item.sources.length !== 1 || item.sources[0] !== 'NVD'} onClick={() => run.mutate(item.id)}>Run {item.name}</button><ProfileSchedule profile={item} /></article>)}
  </section>;
}
