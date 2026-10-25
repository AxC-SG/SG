import React from 'react';
import { useLocation } from 'react-router-dom';
import { PlatformNavigation } from './PlatformNavigation';
import { TenantNavigation } from './TenantNavigation';
import './sidebar.css';

export const Sidebar: React.FC = () => {
  const location = useLocation();

  // Detect if in platform scope
  const isPlatformScope = location.pathname.startsWith('/platform');

  return (
    <aside className="sidebar">
      <div className="sidebar-content">
        {isPlatformScope ? <PlatformNavigation /> : <TenantNavigation />}
      </div>
    </aside>
  );
};
