import React from 'react';

/** Keep the application shell usable when a lazy page or its render fails. */
export class RouteErrorBoundary extends React.Component<
  React.PropsWithChildren<{ resetKey: string }>,
  { failed: boolean; resetKey: string }
> {
  state = { failed: false, resetKey: this.props.resetKey };

  static getDerivedStateFromProps(props: { resetKey: string }, state: { resetKey: string }) {
    return props.resetKey !== state.resetKey ? { failed: false, resetKey: props.resetKey } : null;
  }

  static getDerivedStateFromError() {
    return { failed: true };
  }

  render() {
    if (this.state.failed) {
      return (
        <section className="panel" role="alert">
          <h2>This page could not be loaded</h2>
          <p>Reload the page to try again. You can also use the navigation to open another page.</p>
          <button type="button" className="btn btn-primary" onClick={() => window.location.reload()}>
            Reload page
          </button>
        </section>
      );
    }
    return this.props.children;
  }
}
