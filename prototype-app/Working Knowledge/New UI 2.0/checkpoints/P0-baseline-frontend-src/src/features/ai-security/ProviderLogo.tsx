/** Compact provider mark used wherever a table/list needs to identify AWS vs. Azure at a
 * glance instead of spelling the provider name out — self-contained inline SVGs so there's
 * no external asset request or broken-image risk. Falls back to the raw provider string for
 * any value that isn't AWS/Azure so new providers never render blank. */
export function ProviderLogo({ provider }: { provider: string }) {
  const normalized = provider.trim().toUpperCase();
  if (normalized === 'AWS') {
    return (
      <svg viewBox="0 0 100 34" width="56" height="19" role="img" aria-label="AWS">
        <text x="0" y="22" fontFamily="Arial, Helvetica, sans-serif" fontWeight="700" fontSize="20" fill="#FF9900">aws</text>
        <path
          d="M2 27 C 24 36, 56 36, 78 27"
          fill="none"
          stroke="#FF9900"
          strokeWidth="2.4"
          strokeLinecap="round"
        />
        <path d="M78 27 L 71 24.5 M 78 27 L 72 31.5" fill="none" stroke="#FF9900" strokeWidth="2.4" strokeLinecap="round" />
      </svg>
    );
  }
  if (normalized === 'AZURE') {
    return (
      <svg viewBox="0 0 108 34" width="60" height="19" role="img" aria-label="Azure">
        <polygon points="16,29 27,5 34,5 21,29" fill="#0078D4" />
        <polygon points="21,29 34,5 44,13 30,29" fill="#0078D4" />
        <text x="48" y="24" fontFamily="Arial, Helvetica, sans-serif" fontWeight="600" fontSize="18" fill="#0078D4">Azure</text>
      </svg>
    );
  }
  return <span>{provider}</span>;
}
