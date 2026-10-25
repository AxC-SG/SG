// Exposure data is refreshed in the background at a low cadence. The page
// keeps the last-known timestamp visible instead of interrupting active work.
export const DASHBOARD_REFRESH_INTERVAL_MS = 4 * 60 * 60 * 1000;
export const OPERATIONS_REFRESH_INTERVAL_MS = 15_000;
export const ORG_CVE_STATUS_REFRESH_INTERVAL_MS = 10_000;
export const RUN_QUEUE_REFRESH_INTERVAL_MS = 3_000;
