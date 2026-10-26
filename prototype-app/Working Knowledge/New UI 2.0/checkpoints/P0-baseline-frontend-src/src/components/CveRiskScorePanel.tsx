import React from 'react';
import type { OrgSpecificCveExposureRecord } from '../features/cve-workbench/types';
import { useRiskPolicyQuery } from '../features/cve-workbench/queries';
import { computeCveRiskScore } from '../lib/riskScoring';

type Props = {
  item: OrgSpecificCveExposureRecord;
  mini?: boolean;
};

type PeriodDays = 14 | 30 | 90;

const CHART_VW = 700;
const CHART_VH = 110;
const PAD_L = 28;
const PAD_R = 10;
const PAD_T = 8;
const PAD_B = 22;
const PLOT_W = CHART_VW - PAD_L - PAD_R;
const PLOT_H = CHART_VH - PAD_T - PAD_B;

// Mini chart — doubled height
const MINI_VH = 160;
const MINI_PLOT_H = MINI_VH - PAD_T - PAD_B;

function scoreToY(score: number): number {
  return PAD_T + PLOT_H - (Math.min(Math.max(score, 0), 10) / 10) * PLOT_H;
}

function scoreToYMini(score: number): number {
  return PAD_T + MINI_PLOT_H - (Math.min(Math.max(score, 0), 10) / 10) * MINI_PLOT_H;
}

function idxToX(i: number, n: number): number {
  if (n <= 1) return PAD_L + PLOT_W / 2;
  return PAD_L + (i / (n - 1)) * PLOT_W;
}

function fmtDate(d: Date): string {
  return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
}

function buildPoints(
  journey: Array<{ stage: string; score: number; delta: number; reason: string }>,
  periodDays: PeriodDays,
  yFn: (score: number) => number,
) {
  const now = new Date();
  const start = new Date(now.getTime() - periodDays * 86400_000);
  return journey.map((ev, i) => {
    const frac = journey.length <= 1 ? 0 : i / (journey.length - 1);
    const date = new Date(start.getTime() + frac * periodDays * 86400_000);
    return { ...ev, date, x: idxToX(i, journey.length), y: yFn(ev.score) };
  });
}

function smoothPath(pts: Array<{ x: number; y: number }>): string {
  if (pts.length === 0) return '';
  if (pts.length === 1) return `M ${pts[0].x},${pts[0].y}`;
  return pts.reduce((acc, pt, i) => {
    if (i === 0) return `M ${pt.x},${pt.y}`;
    const prev = pts[i - 1];
    const cpx = prev.x + (pt.x - prev.x) * 0.5;
    return `${acc} C ${cpx},${prev.y} ${cpx},${pt.y} ${pt.x},${pt.y}`;
  }, '');
}

const Y_LABELS = [10, 5, 0];

/** Scout risk score trend chart. Use mini=true for the compact card layout. */
export function CveRiskScorePanel({ item, mini = false }: Props) {
  const [period, setPeriod] = React.useState<PeriodDays>(14);
  const policyQuery = useRiskPolicyQuery();
  const result = React.useMemo(
    () => computeCveRiskScore(item, policyQuery.data),
    [item, policyQuery.data],
  );

  // Memoized so pts/xTicks recompute only when result or period changes
  const journey = React.useMemo(
    () => result.journey.filter(ev => !ev.isNote),
    [result],
  );
  const hasJourney = journey.length > 1;

  const pts = React.useMemo(
    () => buildPoints(journey, period, mini ? scoreToYMini : scoreToY),
    [journey, period, mini],
  );

  const linePath = smoothPath(pts);
  const areaPath = !mini && linePath && pts.length >= 2
    ? `${linePath} L ${pts[pts.length - 1].x},${PAD_T + PLOT_H} L ${pts[0].x},${PAD_T + PLOT_H} Z`
    : '';

  const cvssScore = Math.min(item.cvssScore ?? 0, 10);

  const xTicks = React.useMemo(() => {
    if (pts.length === 0) return [];
    const count = Math.min(pts.length, 5);
    return Array.from({ length: count }, (_, i) => {
      const idx = Math.round((i / (count - 1)) * (pts.length - 1));
      return pts[Math.min(idx, pts.length - 1)];
    });
  }, [pts]);

  if (!hasJourney) return null;

  if (mini) {
    const cvssY = scoreToYMini(cvssScore);
    return (
      <div className="cvrs-mini-card">
        {/* Header: title + period selector */}
        <div className="cvrs-mini-header">
          <span className="cvrs-mini-title">SCOUT RISK SCORE</span>
          <div className="cvrs-period-btns">
            {([14, 30, 90] as PeriodDays[]).map(p => (
              <button key={p} type="button"
                className={`cvrs-period-btn${period === p ? ' active' : ''}`}
                onClick={() => setPeriod(p)}>{p}d</button>
            ))}
          </div>
        </div>

        {/* Score + hover tooltip */}
        <div className="cvrs-mini-score-wrap">
          <div className="cvrs-mini-score-row">
            <span className="cvrs-mini-score-num" style={{ color: result.color }}>
              {result.score.toFixed(1)}
            </span>
            <div className="cvrs-mini-score-meta">
              <span className="cvrs-mini-score-label">{result.label} ✦</span>
              {cvssScore > 0 && (
                <span className="cvrs-mini-vs-cvss">vs CVSS {cvssScore.toFixed(1)} baseline</span>
              )}
            </div>
          </div>
          {/* AI justification tooltip on hover */}
          <div className="cvrs-mini-tooltip" role="tooltip">
            <div className="cvrs-mini-tooltip-heading">✦ Scout Score Reasoning</div>
            {journey.length > 0 && (
              <div className="cvd-score-tooltip-journey">
                {journey.map((ev, i) => (
                  <div key={i} className="cvd-score-tooltip-row">
                    <span className="cvd-score-tooltip-stage">{ev.stage}</span>
                    {ev.delta !== 0 && (
                      <span className={`cvd-score-tooltip-delta${ev.delta > 0 ? ' up' : ' down'}`}>
                        {ev.delta > 0 ? '+' : ''}{ev.delta.toFixed(1)}
                      </span>
                    )}
                    <span className="cvd-score-tooltip-val">→ {ev.score.toFixed(1)}</span>
                  </div>
                ))}
              </div>
            )}
            {result.topReasons.length > 0 && (
              <>
                <div className="cvd-score-tooltip-divider" />
                <div className="cvrs-mini-tooltip-heading">Key drivers</div>
                {result.topReasons.map((r, i) => (
                  <div key={i} className="cvd-score-tooltip-reason">· {r}</div>
                ))}
              </>
            )}
          </div>
        </div>

        {/* SVG chart — uses result.color for line/dots so it matches the score badge */}
        <svg className="cvrs-mini-svg" viewBox={`0 0 ${CHART_VW} ${MINI_VH}`}
          width="100%" preserveAspectRatio="none" aria-hidden="true">
          {/* Grid lines */}
          {[10, 5, 0].map(v => {
            const y = scoreToYMini(v);
            return (
              <g key={v}>
                <line x1={PAD_L} y1={y} x2={CHART_VW - PAD_R} y2={y}
                  stroke="var(--border)" strokeWidth="0.5" opacity="0.5" />
                <text x={PAD_L - 4} y={y + 3} textAnchor="end" fontSize="8" fill="var(--muted)">{v}</text>
              </g>
            );
          })}
          {/* CVSS dashed baseline */}
          {cvssScore > 0 && (
            <>
              <line x1={PAD_L} y1={cvssY} x2={CHART_VW - PAD_R} y2={cvssY}
                stroke="var(--muted)" strokeWidth="1" strokeDasharray="5 4" opacity="0.5" />
              <text x={CHART_VW - PAD_R - 2} y={cvssY - 3}
                textAnchor="end" fontSize="8" fill="var(--muted)">
                CVSS {cvssScore.toFixed(1)}
              </text>
            </>
          )}
          {/* Score line — color matches score badge */}
          {linePath && (
            <path d={linePath} fill="none" stroke={result.color} strokeWidth="2"
              strokeLinejoin="round" strokeLinecap="round" />
          )}
          {/* Dots: red start, green end, score-color middle */}
          {pts.map((pt, i) => (
            <circle key={i} cx={pt.x} cy={pt.y}
              r={i === pts.length - 1 ? 5 : 4}
              fill={i === 0 ? '#dc3545' : i === pts.length - 1 ? '#16a34a' : result.color}
              stroke="var(--panel-solid)" strokeWidth="1.5" />
          ))}
          {/* X-axis date labels — change visibly when period is changed */}
          {xTicks.map((pt, i) => (
            <text key={i} x={pt.x} y={MINI_VH - 4}
              textAnchor="middle" fontSize="8" fill="var(--muted)">
              {fmtDate(pt.date)}
            </text>
          ))}
        </svg>

        {/* Text event list */}
        <div className="cvrs-mini-events">
          {pts.map((pt, i) => (
            <div key={i} className="cvrs-mini-event-row">
              <span className="cvrs-mini-event-dot"
                style={{ background: i === 0 ? '#dc3545' : i === pts.length - 1 ? '#16a34a' : result.color }} />
              <span className="cvrs-mini-event-stage">{pt.stage}</span>
              {pt.delta !== 0 && (
                <span className={`cvrs-mini-event-delta${pt.delta > 0 ? ' up' : ' down'}`}>
                  {pt.delta > 0 ? '+' : ''}{pt.delta.toFixed(1)}
                </span>
              )}
              <span className="cvrs-mini-event-score">→ {pt.score.toFixed(1)}</span>
            </div>
          ))}
        </div>
      </div>
    );
  }

  return (
    <div className="cvrs-panel">

      {/* Toolbar: title + legend + period selector */}
      <div className="cvrs-chart-toolbar">
        <div className="cvrs-legend">
          <span className="cvrs-title">Scout risk score trend</span>
          <span className="cvrs-legend-item">
            <span className="cvrs-legend-line cvrs-legend-line--solid" />
            Scout score
          </span>
          {cvssScore > 0 && (
            <span className="cvrs-legend-item">
              <span className="cvrs-legend-line cvrs-legend-line--dashed" />
              CVSS baseline
            </span>
          )}
          <span className="cvrs-legend-item">
            <span className="cvrs-legend-dot" />
            Scoring event
          </span>
        </div>
        <div className="cvrs-period-btns">
          {([14, 30, 90] as PeriodDays[]).map(p => (
            <button
              key={p}
              type="button"
              className={`cvrs-period-btn${period === p ? ' active' : ''}`}
              onClick={() => setPeriod(p)}
            >
              {p}d
            </button>
          ))}
        </div>
      </div>

      {/* SVG area chart */}
      <svg
        className="cvrs-chart-svg"
        viewBox={`0 0 ${CHART_VW} ${CHART_VH}`}
        width="100%"
        preserveAspectRatio="none"
        aria-hidden="true"
      >
        <defs>
          <linearGradient id="cvrs-area-grad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor={result.color} stopOpacity="0.25" />
            <stop offset="100%" stopColor={result.color} stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {Y_LABELS.map(v => {
          const y = scoreToY(v);
          return (
            <g key={v}>
              <line x1={PAD_L} y1={y} x2={CHART_VW - PAD_R} y2={y}
                stroke="var(--border)" strokeWidth="1"
                strokeDasharray={v === 10 ? '4 4' : undefined} />
              <text x={PAD_L - 4} y={y + 4} textAnchor="end" fontSize="9" fill="var(--muted)">{v}</text>
            </g>
          );
        })}
        {cvssScore > 0 && (
          <line
            x1={PAD_L} y1={scoreToY(cvssScore)} x2={CHART_VW - PAD_R} y2={scoreToY(cvssScore)}
            stroke="var(--muted)" strokeWidth="1.5" strokeDasharray="6 4" opacity="0.55"
          />
        )}
        {areaPath && <path d={areaPath} fill="url(#cvrs-area-grad)" />}
        {linePath && (
          <path d={linePath} fill="none" stroke={result.color} strokeWidth="2"
            strokeLinejoin="round" strokeLinecap="round" />
        )}
        {pts.map((pt, i) => (
          <circle key={i} cx={pt.x} cy={pt.y}
            r={i === pts.length - 1 ? 5 : 4}
            fill={i === pts.length - 1 ? result.color : '#dc3545'}
            stroke="var(--panel-solid)" strokeWidth="1.5" />
        ))}
        {xTicks.map((pt, i) => (
          <text key={i} x={pt.x} y={CHART_VH - 4}
            textAnchor="middle" fontSize="9" fill="var(--muted)">
            {fmtDate(pt.date)}
          </text>
        ))}
      </svg>

      {/* Compact scoring event cards */}
      <div className="cvrs-events-row">
        {pts.map((pt, i) => (
          <div key={i} className="cvrs-event-card">
            <div className="cvrs-event-card-top">
              <span className="cvrs-event-card-dot"
                style={{ background: i === 0 ? 'var(--muted)' : '#dc3545' }} />
              <span className="cvrs-event-date">{fmtDate(pt.date)}</span>
            </div>
            <span className="cvrs-event-name">{pt.stage}</span>
            <div className="cvrs-event-detail">
              {pt.delta !== 0 && (
                <span className={`cvrs-event-delta${pt.delta > 0 ? ' up' : ' down'}`}>
                  {pt.delta > 0 ? '+' : ''}{pt.delta.toFixed(1)}
                </span>
              )}
              {pt.reason && (
                <span className="cvrs-event-reason">{pt.delta !== 0 ? ' · ' : ''}{pt.reason}</span>
              )}
            </div>
          </div>
        ))}
      </div>

    </div>
  );
}
