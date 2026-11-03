import React from 'react';

// Decorative public-site graphics, drawn in code so no image assets ship with the site.

type IconName =
  | 'sparkle'
  | 'server'
  | 'boxes'
  | 'cloud'
  | 'scan'
  | 'wrench'
  | 'hourglass'
  | 'flag'
  | 'branch'
  | 'arrow'
  | 'arrowDown';

const ICON_PATHS: Record<IconName, React.ReactNode> = {
  sparkle: (
    <>
      <path d="M10 3.5 11.6 8.4 16.5 10 11.6 11.6 10 16.5 8.4 11.6 3.5 10 8.4 8.4Z" />
      <path d="M16 2.5v3M14.5 4h3" />
    </>
  ),
  server: (
    <>
      <rect x="3" y="3.5" width="14" height="5.5" rx="1.5" />
      <rect x="3" y="11" width="14" height="5.5" rx="1.5" />
      <path d="M6 6.25h.01M6 13.75h.01" />
    </>
  ),
  boxes: (
    <>
      <path d="M10 2.8 13.4 4.7v3.8L10 10.4 6.6 8.5V4.7Z" />
      <path d="M6.6 10.4 10 12.3v3.8l-3.4 1.9-3.4-1.9v-3.8Z" />
      <path d="M13.4 10.4l3.4 1.9v3.8l-3.4 1.9-3.4-1.9v-3.8Z" />
    </>
  ),
  cloud: <path d="M6 15.5h8.2a3.3 3.3 0 0 0 .4-6.6 4.8 4.8 0 0 0-9.2 1.1A2.8 2.8 0 0 0 6 15.5Z" />,
  scan: (
    <>
      <path d="M3.5 7V4.5a1 1 0 0 1 1-1H7M13 3.5h2.5a1 1 0 0 1 1 1V7M16.5 13v2.5a1 1 0 0 1-1 1H13M7 16.5H4.5a1 1 0 0 1-1-1V13" />
      <circle cx="9.6" cy="9.6" r="2.4" />
      <path d="m11.4 11.4 1.8 1.8" />
    </>
  ),
  wrench: (
    <path d="M12.4 3.3a4 4 0 0 0-4.6 5.4L3.3 13.2a1.6 1.6 0 0 0 2.3 2.3l4.5-4.5a4 4 0 0 0 5.4-4.6l-2.4 2.4-2.1-.4-.4-2.1Z" />
  ),
  hourglass: (
    <>
      <path d="M5 3h10M5 17h10" />
      <path d="M6.5 3v2.5L10 10l3.5-4.5V3M6.5 17v-2.5L10 10l3.5 4.5V17" />
    </>
  ),
  flag: <path d="M5 17V3.5M5 4h9l-1.8 3.2L14 10.5H5" />,
  branch: (
    <>
      <circle cx="5.5" cy="5" r="1.8" />
      <circle cx="14.5" cy="15" r="1.8" />
      <path d="M5.5 6.8V17M14.5 13.2V9.5a3 3 0 0 0-3-3H9" />
      <path d="m10.5 5-1.5 1.5L10.5 8" />
    </>
  ),
  arrow: <path d="M6 14 14 6M7.5 6H14v6.5" />,
  arrowDown: <path d="M10 4v12M5.5 11.5 10 16l4.5-4.5" />
};

export function SiteIcon({ name, className }: { name: IconName; className?: string }) {
  return (
    <svg
      className={className ? `sgw-icon ${className}` : 'sgw-icon'}
      viewBox="0 0 20 20"
      fill="none"
      stroke="currentColor"
      strokeWidth="1.4"
      strokeLinecap="round"
      strokeLinejoin="round"
      aria-hidden="true"
      focusable="false"
    >
      {ICON_PATHS[name]}
    </svg>
  );
}

// Hero: a wireframe exposure surface rising out of a flat plane.
const MESH_COLS = 17;
const MESH_ROWS = 11;

function meshPoint(col: number, row: number): [number, number] {
  const u = (col / (MESH_COLS - 1)) * 2 - 1;
  const v = row / (MESH_ROWS - 1);
  const spread = 0.55 + 0.45 * v;
  const x = 300 + u * 290 * spread;
  const base = 120 + v * 250;
  const lift = 250 * Math.exp(-((u * u) / 0.16 + ((v - 0.45) * (v - 0.45)) / 0.12));
  return [Math.round(x * 10) / 10, Math.round((base - lift) * 10) / 10];
}

function polyline(points: Array<[number, number]>): string {
  return points.map(([x, y]) => `${x},${y}`).join(' ');
}

const MESH_ROW_LINES = Array.from({ length: MESH_ROWS }, (_, row) =>
  polyline(Array.from({ length: MESH_COLS }, (_, col) => meshPoint(col, row)))
);
const MESH_COL_LINES = Array.from({ length: MESH_COLS }, (_, col) =>
  polyline(Array.from({ length: MESH_ROWS }, (_, row) => meshPoint(col, row)))
);
const MESH_RIDGE = polyline(Array.from({ length: MESH_COLS }, (_, col) => meshPoint(col, 4)));
const MESH_EDGE = polyline([
  ...Array.from({ length: MESH_COLS }, (_, col) => meshPoint(col, MESH_ROWS - 1)),
  meshPoint(MESH_COLS - 1, 0)
]);
const MESH_MARKERS: Array<[number, number]> = [meshPoint(6, 3), meshPoint(10, 3), meshPoint(5, 6), meshPoint(12, 6), meshPoint(8, 4)];

export function HeroSurfaceGraphic() {
  return (
    <svg className="sgw-hero-graphic" viewBox="0 0 600 400" aria-hidden="true" focusable="false">
      <defs>
        <radialGradient id="sgw-hero-glow" cx="50%" cy="45%" r="45%">
          <stop offset="0%" stopColor="#d50a2a" stopOpacity="0.28" />
          <stop offset="100%" stopColor="#d50a2a" stopOpacity="0" />
        </radialGradient>
      </defs>
      <ellipse cx="300" cy="190" rx="260" ry="150" fill="url(#sgw-hero-glow)" />
      <g fill="none" stroke="rgba(255,255,255,0.16)" strokeWidth="0.8">
        {MESH_ROW_LINES.map((points) => <polyline key={points} points={points} />)}
        {MESH_COL_LINES.map((points) => <polyline key={points} points={points} />)}
      </g>
      <g fill="none" stroke="#e11d3a" strokeWidth="1.4">
        <polyline points={MESH_RIDGE} />
        <polyline points={MESH_EDGE} />
      </g>
      <g fill="#e11d3a">
        {MESH_MARKERS.map(([x, y]) => <rect key={`${x}-${y}`} x={x - 3.5} y={y - 3.5} width="7" height="7" />)}
      </g>
    </svg>
  );
}

// AI Grid in focus: nested diamonds converging on the AI core.
const DIAMOND_SCALES = [0.86, 0.72, 0.58, 0.44, 0.32];
const DIAMOND_RAYS = Array.from({ length: 16 }, (_, index) => index / 16);

function diamondPoints(scale: number): string {
  const rx = 225 * scale;
  const ry = 165 * scale;
  return `240,${180 - ry} ${240 + rx},180 240,${180 + ry} ${240 - rx},180`;
}

function diamondEdgePoint(t: number): [number, number] {
  const corners: Array<[number, number]> = [[240, 15], [465, 180], [240, 345], [15, 180]];
  const scaled = t * 4;
  const index = Math.floor(scaled);
  const local = scaled - index;
  const [ax, ay] = corners[index % 4];
  const [bx, by] = corners[(index + 1) % 4];
  return [ax + (bx - ax) * local, ay + (by - ay) * local];
}

export function AiDiamondGraphic() {
  return (
    <svg className="sgw-diamond-graphic" viewBox="0 0 480 360" aria-hidden="true" focusable="false">
      <defs>
        <radialGradient id="sgw-diamond-glow" cx="50%" cy="50%" r="35%">
          <stop offset="0%" stopColor="#d50a2a" stopOpacity="0.35" />
          <stop offset="100%" stopColor="#d50a2a" stopOpacity="0" />
        </radialGradient>
      </defs>
      <g stroke="rgba(255,255,255,0.13)" strokeWidth="0.8" fill="none">
        {DIAMOND_RAYS.map((t) => {
          const [x, y] = diamondEdgePoint(t);
          return <line key={t} x1="240" y1="180" x2={x} y2={y} />;
        })}
        {DIAMOND_SCALES.map((scale) => <polygon key={scale} points={diamondPoints(scale)} />)}
      </g>
      <ellipse cx="240" cy="180" rx="120" ry="90" fill="url(#sgw-diamond-glow)" />
      <polygon points={diamondPoints(1)} fill="none" stroke="#e11d3a" strokeWidth="1.6" />
      <g fill="#e11d3a">
        <rect x="236" y="58" width="8" height="8" />
        <rect x="376" y="176" width="8" height="8" />
        <rect x="236" y="294" width="8" height="8" />
        <rect x="96" y="176" width="8" height="8" />
      </g>
      <rect x="184" y="124" width="112" height="112" fill="#111318" stroke="#e11d3a" strokeWidth="1.4" />
      <text x="240" y="190" textAnchor="middle" className="sgw-diamond-core">AI</text>
      <text x="240" y="214" textAnchor="middle" className="sgw-diamond-label">GRID</text>
    </svg>
  );
}

// The connected advantage: one path linking points across separate surfaces.
const NET_COLS = 11;
const NET_ROWS = 4;
const NET_CELL_W = 41;
const NET_CELL_H = 39;
const NET_PATH: Array<[number, number]> = [[4, 0], [7, 0], [8, 1], [6, 3], [3, 3], [2, 2], [4, 0], [6, 3]];

function netPoint(col: number, row: number): [number, number] {
  return [col * NET_CELL_W + NET_CELL_W / 2, row * NET_CELL_H + NET_CELL_H / 2];
}

export function ConnectionsGraphic() {
  const width = NET_COLS * NET_CELL_W;
  const height = NET_ROWS * NET_CELL_H;
  const pathPoints = NET_PATH.map(([col, row]) => netPoint(col, row));
  return (
    <svg className="sgw-network-graphic" viewBox={`-1 -1 ${width + 2} ${height + 2}`} aria-hidden="true" focusable="false">
      <g stroke="rgba(255,255,255,0.12)" strokeWidth="1" fill="none">
        <rect x="0" y="0" width={width} height={height} />
        {Array.from({ length: NET_COLS - 1 }, (_, index) => (
          <line key={`c${index}`} x1={(index + 1) * NET_CELL_W} y1="0" x2={(index + 1) * NET_CELL_W} y2={height} />
        ))}
        {Array.from({ length: NET_ROWS - 1 }, (_, index) => (
          <line key={`r${index}`} x1="0" y1={(index + 1) * NET_CELL_H} x2={width} y2={(index + 1) * NET_CELL_H} />
        ))}
      </g>
      <g fill="rgba(255,255,255,0.55)">
        {Array.from({ length: NET_COLS * NET_ROWS }, (_, index) => {
          const [x, y] = netPoint(index % NET_COLS, Math.floor(index / NET_COLS));
          return <rect key={index} x={x - 1.5} y={y - 1.5} width="3" height="3" />;
        })}
      </g>
      <polyline points={polyline(pathPoints)} fill="none" stroke="#e11d3a" strokeWidth="1.4" strokeLinejoin="round" />
      <g fill="#e11d3a">
        {[...pathPoints.slice(0, 6), netPoint(9, 2)].map(([x, y]) => (
          <rect key={`${x}-${y}`} x={x - 3} y={y - 3} width="6" height="6" />
        ))}
      </g>
    </svg>
  );
}
