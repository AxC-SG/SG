import { act, render, screen } from '@testing-library/react';
import React from 'react';
import { MemoryRouter, Route, Routes, useLocation, useNavigate, useParams } from 'react-router-dom';
import { describe, expect, it } from 'vitest';
import { PageHeaderProvider } from './PageHeader';
import { usePageHeader, useRouteHeader } from './pageHeaderState';

const seen: Array<{ pathname: string; title: string }> = [];

function ShellHeader() {
  const { pathname } = useLocation();
  const header = useRouteHeader(pathname, 'Records');
  seen.push({ pathname, title: header.title });
  return (
    <header>
      <h1>{header.title}</h1>
      {header.actions}
    </header>
  );
}

// The record title is only known after the record "loads" (one effect later).
function RecordPage() {
  const { id } = useParams();
  const [loaded, setLoaded] = React.useState<string | null>(null);
  React.useEffect(() => setLoaded(id ?? null), [id]);
  usePageHeader(loaded === id && id ? { title: `Record ${id}`, actions: <button type="button">Edit {id}</button> } : null);
  return <p>body {id}</p>;
}

let goTo: (path: string) => void = () => undefined;
function Navigator() {
  const navigate = useNavigate();
  React.useEffect(() => {
    goTo = (path) => navigate(path);
  }, [navigate]);
  return null;
}

function renderShell(path: string) {
  return render(
    <MemoryRouter initialEntries={[path]}>
      <PageHeaderProvider>
        <Navigator />
        <ShellHeader />
        <Routes>
          <Route path="/records/:id" element={<RecordPage key="record" />} />
          <Route path="/plain" element={<p>plain</p>} />
        </Routes>
      </PageHeaderProvider>
    </MemoryRouter>
  );
}

describe('PageHeader', () => {
  it('uses the route fallback until the page registers, then its title and actions', async () => {
    seen.length = 0;
    renderShell('/records/1');
    expect(await screen.findByRole('heading', { level: 1, name: 'Record 1' })).toBeInTheDocument();
    expect(screen.getByRole('button', { name: 'Edit 1' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 1 })).toHaveLength(1);
  });

  it('never shows the previous record title on the next route', async () => {
    seen.length = 0;
    renderShell('/records/1');
    await screen.findByRole('heading', { level: 1, name: 'Record 1' });
    act(() => goTo('/records/2'));
    expect(await screen.findByRole('heading', { level: 1, name: 'Record 2' })).toBeInTheDocument();
    expect(seen.filter((entry) => entry.pathname === '/records/2').map((entry) => entry.title)).not.toContain('Record 1');
    act(() => goTo('/plain'));
    expect(screen.getByRole('heading', { level: 1, name: 'Records' })).toBeInTheDocument();
    expect(screen.queryByRole('button', { name: /Edit/ })).not.toBeInTheDocument();
    expect(seen.filter((entry) => entry.pathname === '/plain').map((entry) => entry.title)).toEqual(expect.arrayContaining(['Records']));
    expect(seen.filter((entry) => entry.pathname === '/plain').every((entry) => entry.title === 'Records')).toBe(true);
  });

  it('is inert outside a provider', () => {
    function Lone() {
      usePageHeader({ title: 'Ignored' });
      return <span>{useRouteHeader('/x', 'Fallback').title}</span>;
    }
    render(<MemoryRouter><Lone /></MemoryRouter>);
    expect(screen.getByText('Fallback')).toBeInTheDocument();
  });
});
