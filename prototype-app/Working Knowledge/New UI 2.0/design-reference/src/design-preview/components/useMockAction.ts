import React from 'react';
import { usePreview } from '../previewContext';

/** Deterministic local outcomes for review. Never calls an API or a cloud provider. */
export function useMockAction() {
  const { scenario } = usePreview();
  const [pending, setPending] = React.useState(false);
  const [error, setError] = React.useState('');
  const [message, setMessage] = React.useState('');
  const timer = React.useRef<ReturnType<typeof setTimeout>>();
  React.useEffect(() => () => clearTimeout(timer.current), []);
  function run(success: string, onSuccess?: () => void) {
    if (pending) return;
    setPending(true); setError(''); setMessage('');
    timer.current = setTimeout(() => {
      setPending(false);
      if (scenario === 'save-error') setError('The change could not be saved. Your edits are retained. Retry when the service is available.');
      else { onSuccess?.(); setMessage(success); }
    }, 550);
  }
  return { pending, error, message, run };
}
