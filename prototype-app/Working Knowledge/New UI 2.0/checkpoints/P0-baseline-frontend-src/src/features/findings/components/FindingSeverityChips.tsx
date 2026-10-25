type FindingSeverityChipsProps = {
  critical: number;
  high: number;
  other: number;
};

/** Shared findings-column rendering: one colored chip per severity bucket (critical/high/
 * medium+low) holding that bucket's count, instead of a single total or text breakdown —
 * used on the AI asset inventory, host inventory, and CBOM components tables so the same
 * counts read the same way everywhere. */
export function FindingSeverityChips({ critical, high, other }: FindingSeverityChipsProps) {
  return (
    <div className="finding-severity-chips">
      <span className="finding-severity-chip finding-severity-chip--critical" title="Critical">
        {critical.toLocaleString()}
      </span>
      <span className="finding-severity-chip finding-severity-chip--high" title="High">
        {high.toLocaleString()}
      </span>
      <span className="finding-severity-chip finding-severity-chip--other" title="Medium / Low">
        {other.toLocaleString()}
      </span>
    </div>
  );
}
