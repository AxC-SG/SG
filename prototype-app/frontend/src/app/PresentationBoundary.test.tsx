import React from 'react';
import { cleanup, fireEvent, render, screen, waitFor } from '@testing-library/react';
import { afterEach, describe, expect, it } from 'vitest';
import { BrowserRouter, Link, MemoryRouter, useNavigate } from 'react-router-dom';
import { PresentationBoundary } from './PresentationBoundary';

function Navigation() {
  const navigate = useNavigate();
  return <>
    <Link to="/demo/blog">Blog</Link>
    <Link to="/login">Login</Link>
    <button onClick={() => navigate(-1)}>Back</button>
    <button onClick={() => navigate(1)}>Forward</button>
  </>;
}

afterEach(() => {
  cleanup();
  document.documentElement.removeAttribute('data-ui');
  document.documentElement.removeAttribute('data-theme');
  localStorage.clear();
  window.history.replaceState(null, '', '/');
});

describe('PresentationBoundary', () => {
  it.each(['/demo', '/demo/blog', '/demo/request', '/demo/request/success', '/demo/expired', '/login', '/setup/token', '/invite/token', '/tenant-invite/token', '/findings'])('applies the boundary on initial render of %s', (pathname) => {
    // A stale attribute from the previous route must never leak onto a public page.
    document.documentElement.setAttribute('data-ui', '1');
    render(<React.StrictMode><MemoryRouter initialEntries={[pathname]}>
      <PresentationBoundary />
    </MemoryRouter></React.StrictMode>);
    const expected = pathname.startsWith('/demo') ? null : '2';
    expect(document.documentElement.getAttribute('data-ui')).toBe(expected);
  });

  it.each(['dark', 'light'])('isolates public pages through real links, Back and Forward in %s theme', async (theme) => {
    const root = document.documentElement;
    root.setAttribute('data-theme', theme);
    localStorage.setItem('scoutai-theme', theme);
    window.history.replaceState(null, '', '/findings');
    render(<React.StrictMode><BrowserRouter>
      <PresentationBoundary /><Navigation />
    </BrowserRouter></React.StrictMode>);
    const check = (path: string, ui: string | null) => {
      expect(window.location.pathname).toBe(path);
      expect(root.getAttribute('data-ui')).toBe(ui);
      expect(root).toHaveAttribute('data-theme', theme);
      expect(localStorage.getItem('scoutai-theme')).toBe(theme);
    };
    check('/findings', '2');
    fireEvent.click(screen.getByRole('link', { name: 'Blog' }));
    check('/demo/blog', null);
    fireEvent.click(screen.getByRole('link', { name: 'Login' }));
    check('/login', '2');
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    await waitFor(() => check('/demo/blog', null));
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    await waitFor(() => check('/findings', '2'));
    fireEvent.click(screen.getByRole('button', { name: 'Forward' }));
    await waitFor(() => check('/demo/blog', null));
    fireEvent.click(screen.getByRole('button', { name: 'Forward' }));
    await waitFor(() => check('/login', '2'));
  });
});
