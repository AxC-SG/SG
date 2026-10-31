import { AsyncSection } from '../../components/AsyncSection';

type Props = {
  connectorName: string;
  error: unknown;
  onRetry: () => void;
  retrying: boolean;
};

// A connector whose saved settings failed to load is not "not yet configured". Its form stays
// hidden until a retry succeeds, so Save cannot replace the saved values with blank defaults.
export function ConnectorConfigLoadError({ connectorName, error, onRetry, retrying }: Props) {
  const reason = error instanceof Error && error.message ? error.message : 'Unknown error';
  return (
    <section className="panel">
      <AsyncSection
        state="error"
        errorMessage={`The saved ${connectorName} settings could not be loaded (${reason}). The form is hidden so a save cannot overwrite them; retry to continue.`}
        onRetry={onRetry}
        retrying={retrying}
      />
    </section>
  );
}
