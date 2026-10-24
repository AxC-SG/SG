/** Shared presentation only. Each page keeps its own query and interaction contract. */
export function FindingsFamilyNav({ active, onNavigate }: { active: 'vulnerability' | 'ai'; onNavigate: (route: string) => void }) {
  return <nav className="dp-family-nav" aria-label="Findings family">
    <button type="button" className={active === 'vulnerability' ? 'active' : ''} aria-current={active === 'vulnerability' ? 'page' : undefined} onClick={() => onNavigate('/findings')}>Vulnerability Findings</button>
    <button type="button" className={active === 'ai' ? 'active' : ''} aria-current={active === 'ai' ? 'page' : undefined} onClick={() => onNavigate('/findings/ai')}>AI Findings</button>
  </nav>;
}
