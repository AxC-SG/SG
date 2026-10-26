import React from 'react';
import { Link, useLocation } from 'react-router-dom';
import { Users, Settings, BookOpen, FileText, MoreVertical } from 'lucide-react';

export const PlatformNavigation: React.FC = () => {
  const location = useLocation();
  const isActive = (path: string) => location.pathname === path;

  return (
    <nav className="navigation platform-navigation">
      <div className="nav-section">
        <h3 className="nav-title">Platform Management</h3>
        <ul className="nav-list">
          <li className={isActive('/platform') ? 'active' : ''}>
            <Link to="/platform" className="nav-item">
              <span className="nav-icon">🏢</span>
              <span>Tenant Management</span>
            </Link>
          </li>

          <li className={isActive('/platform/ai-policies') ? 'active' : ''}>
            <Link to="/platform/ai-policies" className="nav-item">
              <span className="nav-icon">🤖</span>
              <span>AI Policies</span>
              <span className="badge-new">Gov</span>
            </Link>
          </li>
        </ul>
      </div>

      <div className="nav-section">
        <h3 className="nav-title">Administration</h3>
        <ul className="nav-list">
          <li className={isActive('/platform/administration') ? 'active' : ''}>
            <Link to="/platform/administration" className="nav-item">
              <Users size={18} />
              <span>Users</span>
            </Link>
          </li>

          <li className={isActive('/platform/invites') ? 'active' : ''}>
            <Link to="/platform/invites" className="nav-item">
              <FileText size={18} />
              <span>Invites</span>
            </Link>
          </li>

          <li className={isActive('/platform/roles') ? 'active' : ''}>
            <Link to="/platform/roles" className="nav-item">
              <Settings size={18} />
              <span>Roles & Permissions</span>
            </Link>
          </li>

          <li className={isActive('/platform/service-accounts') ? 'active' : ''}>
            <Link to="/platform/service-accounts" className="nav-item">
              <MoreVertical size={18} />
              <span>Service Accounts</span>
            </Link>
          </li>
        </ul>
      </div>

      <div className="nav-section">
        <h3 className="nav-title">Audit & Compliance</h3>
        <ul className="nav-list">
          <li className={isActive('/platform/audit') ? 'active' : ''}>
            <Link to="/platform/audit" className="nav-item">
              <BookOpen size={18} />
              <span>Platform Audit</span>
            </Link>
          </li>
        </ul>
      </div>
    </nav>
  );
};
