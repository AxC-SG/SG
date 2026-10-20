import { useSccmCmdbConfigQuery } from '../features/connect/queries';

export function SccmConnectorPage() {
  const configQuery = useSccmCmdbConfigQuery();
  return (
    <section className="page-section">
      <h1>SCCM connector</h1>
      <div className="notice" role="status">
        SCCM live JDBC is disabled for the assisted pilot. Saved configurations cannot be changed,
        tested or synchronized. Existing inventory remains available.
      </div>
      {configQuery.data?.configured ? <p>A saved configuration is retained for future review.</p> : null}
      {configQuery.isError ? <div className="notice error">Unable to read connector status.</div> : null}
    </section>
  );
}
