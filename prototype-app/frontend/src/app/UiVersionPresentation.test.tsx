import React from 'react';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';
import { afterEach, describe, expect, it, vi } from 'vitest';
import { Link, MemoryRouter, useNavigate } from 'react-router-dom';
import { UiVersionPresentation } from './UiVersionPresentation';

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
  vi.unstubAllEnvs();
  document.documentElement.removeAttribute('data-ui');
});

describe('UiVersionPresentation', () => {
  it('restores public presentation on links and re-applies app presentation on history navigation', () => {
    vi.stubEnv('VITE_UI_VERSION', '2');
    render(<React.StrictMode><MemoryRouter initialEntries={['/findings']}>
      <UiVersionPresentation /><Navigation />
    </MemoryRouter></React.StrictMode>);
    const root = document.documentElement;
    expect(root).toHaveAttribute('data-ui', '2');
    fireEvent.click(screen.getByRole('link', { name: 'Blog' }));
    expect(root).not.toHaveAttribute('data-ui');
    fireEvent.click(screen.getByRole('link', { name: 'Login' }));
    expect(root).toHaveAttribute('data-ui', '2');
    fireEvent.click(screen.getByRole('button', { name: 'Back' }));
    expect(root).not.toHaveAttribute('data-ui');
    fireEvent.click(screen.getByRole('button', { name: 'Forward' }));
    expect(root).toHaveAttribute('data-ui', '2');
  });

  it('keeps the legacy build unchanged across route transitions', () => {
    vi.stubEnv('VITE_UI_VERSION', '1');
    render(<MemoryRouter initialEntries={['/demo/blog']}>
      <UiVersionPresentation /><Navigation />
    </MemoryRouter>);
    expect(document.documentElement).not.toHaveAttribute('data-ui');
    fireEvent.click(screen.getByRole('link', { name: 'Login' }));
    expect(document.documentElement).not.toHaveAttribute('data-ui');
  });
});
