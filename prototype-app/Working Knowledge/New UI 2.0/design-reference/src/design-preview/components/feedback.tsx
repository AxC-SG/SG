import React from 'react';
import { AlertTriangle, CheckCircle2, Info, Loader2, OctagonAlert, RefreshCw, X } from 'lucide-react';

type Tone = 'info' | 'success' | 'warning' | 'danger';

const TONE_ICON: Record<Tone, React.ReactNode> = {
  info: <Info size={15} />,
  success: <CheckCircle2 size={15} />,
  warning: <AlertTriangle size={15} />,
  danger: <OctagonAlert size={15} />,
};

/**
 * Inline notice. Replaces today's `.notice`, `.notice.success`, `.notice.error`.
 * Keep the same role the call site uses today (`status` for notices, `alert` for errors).
 */
export function Alert({ tone = 'info', title, children, action, role }: {
  tone?: Tone;
  title?: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
  role?: 'status' | 'alert';
}) {
  return (
    <div className={`dp-alert dp-alert--${tone}`} role={role ?? (tone === 'danger' ? 'alert' : 'status')}>
      <span className="dp-alert-icon">{TONE_ICON[tone]}</span>
      <div className="dp-alert-body">
        {title ? <strong>{title}</strong> : null}
        {children ? <div>{children}</div> : null}
      </div>
      {action ? <div className="dp-alert-action">{action}</div> : null}
    </div>
  );
}

export function Spinner({ size = 14, label }: { size?: number; label?: string }) {
  return (
    <span className="dp-spinner" role={label ? 'status' : undefined}>
      <Loader2 size={size} />
      {label ? <span>{label}</span> : null}
    </span>
  );
}

export function Skeleton({ width = '100%', height = 12, radius = 6 }: { width?: number | string; height?: number; radius?: number }) {
  return <span className="dp-skeleton" style={{ width, height, borderRadius: radius }} aria-hidden="true" />;
}

export function ProgressBar({ value, max = 100, tone = 'accent', label }: { value: number; max?: number; tone?: string; label?: string }) {
  const pct = Math.max(0, Math.min(100, (value / max) * 100));
  return (
    <div className="dp-progress" role="progressbar" aria-valuenow={value} aria-valuemin={0} aria-valuemax={max} aria-label={label}>
      <span className={`dp-progress-fill dp-progress-fill--${tone}`} style={{ width: `${pct}%` }} />
    </div>
  );
}

export function EmptyState({ icon, title, children, action }: {
  icon: React.ReactNode;
  title: string;
  children?: React.ReactNode;
  action?: React.ReactNode;
}) {
  return (
    <div className="dp-empty-state">
      <div className="dp-empty-icon">{icon}</div>
      <strong>{title}</strong>
      {children ? <p>{children}</p> : null}
      {action}
    </div>
  );
}

/** Replaces PageFreshnessStatus visuals; same inputs (updatedAt, isRefreshing, refreshLabel). */
export function FreshnessStatus({ updatedAt, isRefreshing, refreshLabel = 'Refreshing current view…' }: {
  updatedAt: string;
  isRefreshing?: boolean;
  refreshLabel?: string;
}) {
  return (
    <div className="dp-freshness" role="status" aria-live="polite">
      {isRefreshing ? <><RefreshCw size={12} className="dp-spin" />{refreshLabel}</> : <><span className="dp-live-dot" />Updated {updatedAt}</>}
    </div>
  );
}

type ToastItem = { id: number; tone: Tone; message: string };
const ToastContext = React.createContext<(tone: Tone, message: string) => void>(() => undefined);

export function ToastProvider({ children }: { children: React.ReactNode }) {
  const [toasts, setToasts] = React.useState<ToastItem[]>([]);
  const push = React.useCallback((tone: Tone, message: string) => {
    const id = Date.now() + Math.random();
    setToasts((current) => [...current, { id, tone, message }]);
    window.setTimeout(() => setToasts((current) => current.filter((t) => t.id !== id)), 4200);
  }, []);
  return (
    <ToastContext.Provider value={push}>
      {children}
      <div className="dp-toasts" aria-live="polite">
        {toasts.map((toast) => (
          <div key={toast.id} className={`dp-toast dp-toast--${toast.tone}`} role="status">
            <span className="dp-alert-icon">{TONE_ICON[toast.tone]}</span>
            <span>{toast.message}</span>
            <button type="button" className="dp-icon-btn sm" aria-label="Dismiss" onClick={() => setToasts((c) => c.filter((t) => t.id !== toast.id))}><X size={12} /></button>
          </div>
        ))}
      </div>
    </ToastContext.Provider>
  );
}

// eslint-disable-next-line react-refresh/only-export-components -- hook is colocated with its provider on purpose.
export function useToast() {
  return React.useContext(ToastContext);
}
