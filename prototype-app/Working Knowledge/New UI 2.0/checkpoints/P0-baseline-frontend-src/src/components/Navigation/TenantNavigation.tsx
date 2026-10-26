import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import {
  AlertCircle,
  Shield,
  Database,
  Network,
  Settings,
  Wrench,
  BookOpen,
} from 'lucide-react';

export const TenantNavigation: React.FC = () => {
  const location = useLocation();

  const isActive = (path: string) => location.pathname.startsWith(path);
  const isCurrent = (path: string) => location.pathname === path;

  return (
    <nav className="navigation tenant-navigation">
      <div className="nav-section">
        <h3 className="nav-title">Dashboard</h3>
        <ul className="nav-list">
          <li className={isCurrent('/exposure') ? 'active' : ''}>
            <Link to="/exposure" className="nav-item">
              <AlertCircle size={18} />
              <span>Exposure</span>
            </Link>
          </li>
        </ul>
      </div>

      <div className="nav-section">
        <h3 className="nav-title">Findings & Remediation</h3>
        <ul className="nav-list">
          <li className={isCurrent('/findings') ? 'active' : ''}>
            <Link to="/findings" className="nav-item">
              <Shield size={18} />
              <span>Findings</span>
            </Link>
          </li>

          <li className={isActive('/vuln-repo') ? 'active' : ''}>
            <Link to="/vuln-repo" className="nav-item">
              <BookOpen size={18} />
              <span>Vulnerability Repository</span>
            </Link>
          </li>

          <li className={isCurrent('/campaigns') ? 'active' : ''}>
            <Link to="/campaigns" className="nav-item">
              <Wrench size={18} />
              <span>Campaigns</span>
            </Link>
          </li>
        </ul>
      </div>

      <div className="nav-section">
        <h3 className="nav-title">Inventory</h3>
        <ul className="nav-list">
          <li className={isActive('/inventory') ? 'active' : ''}>
            <Link to="/inventory" className="nav-item">
              <Database size={18} />
              <span>Inventory</span>
            </Link>
          </li>
        </ul>
      </div>

      <div className="nav-section">
        <h3 className="nav-title">Sources & Integration</h3>
        <ul className="nav-list">
          <li className={isActive('/connect') ? 'active' : ''}>
            <Link to="/connect" className="nav-item">
              <Network size={18} />
              <span>Connect</span>
            </Link>
          </li>
        </ul>
      </div>

      <div className="nav-section">
        <h3 className="nav-title">Configuration</h3>
        <ul className="nav-list">
          <li className={isActive('/configurations') ? 'active' : ''}>
            <Link to="/configurations" className="nav-item">
              <Settings size={18} />
              <span>Configurations</span>
            </Link>
          </li>
        </ul>
      </div>
    </nav>
  );
};
