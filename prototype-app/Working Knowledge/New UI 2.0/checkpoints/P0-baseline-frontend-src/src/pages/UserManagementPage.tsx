import React from 'react';
import { Navigate, useNavigate, useParams } from 'react-router-dom';
import {
  type AdminRouteView,
  normalizeAdminRouteView,
  pathForAdminView,
} from '../app/routes';
import {
  useAuditEventsQuery,
  useCancelTenantInviteMutation,
  useCreateTenantBulkInvitesMutation,
  useCreateTenantInviteMutation,
  useAuthContextQuery,
  useCreateServiceAccountMutation,
  useDeactivateServiceAccountMutation,
  useReactivateServiceAccountMutation,
  useDeleteServiceAccountMutation,
  useDeleteTenantMemberMutation,
  useResendTenantInviteMutation,
  useServiceAccountsQuery,
  useTenantInvitesQuery,
  useTenantMembersQuery,
  useUpdateTenantMemberMutation,
} from '../features/admin/queries';
import { api } from '../api/client';
import { parseTenantInviteCsv, type ParsedBulkInviteRow } from '../features/admin/csv';
import type { AuditEvent, ServiceAccount, TenantBulkInviteResponse, TenantInvite, TenantMember } from '../features/admin/types';
import { canExportAudit, canManageServiceAccounts, canManageTenant, canManageUsers } from '../features/auth/roles';

type RoleKey = 'Admin' | 'Analyst' | 'Viewer';

const ROLE_KEYS: RoleKey[] = ['Admin', 'Analyst', 'Viewer'];

const ROLE_DESCRIPTIONS: Record<RoleKey, string> = {
  Admin: 'Operational administration across users, integrations, inventory, and findings.',
  Analyst: 'Triage ownership, risk acceptance, VEX decisions, investigation workflow, and finding disposition.',
  Viewer: 'Read-only access for engineering leaders, auditors, and partner teams.',
};

const ROLE_MATRIX = [
  { capability: 'Invite and remove users', admin: true, analyst: false, viewer: false },
  { capability: 'Change roles and scopes', admin: true, analyst: false, viewer: false },
  { capability: 'Approve VEX and risk acceptance', admin: true, analyst: true, viewer: false },
  { capability: 'Manage service accounts', admin: true, analyst: false, viewer: false },
  { capability: 'Suppress findings / risk acceptance', admin: true, analyst: true, viewer: false },
  { capability: 'Edit risk policy and SLA', admin: true, analyst: false, viewer: false },
  { capability: 'Trigger ingestion and connectors', admin: true, analyst: false, viewer: false },
  { capability: 'Investigate findings', admin: true, analyst: true, viewer: false },
  { capability: 'Export audit log', admin: true, analyst: true, viewer: false },
  { capability: 'View dashboards and reports', admin: true, analyst: true, viewer: true },
];

const STATUS_PILL_BY_API: Record<string, string> = {
  ACTIVE: 'status-pill status-open',
  INVITED: 'status-pill status-investigating',
  SUSPENDED: 'status-pill status-suppressed',
  PAUSED: 'status-pill status-suppressed',
};

function statusPillClass(status: string): string {
  return STATUS_PILL_BY_API[status.toUpperCase()] ?? 'status-pill';
}

function formatStatus(status: string): string {
  if (!status) return '—';
  const upper = status.toUpperCase();
  return upper.charAt(0) + upper.slice(1).toLowerCase();
}

function formatRole(role: string | null | undefined): string {
  if (!role) return 'Unassigned';
  return role
    .split('_')
    .map((part) => (part.length === 0 ? '' : part.charAt(0).toUpperCase() + part.slice(1).toLowerCase()))
    .filter((part) => part.length > 0)
    .join(' ');
}

function roleBucket(role: string | null | undefined): RoleKey {
  const normalized = formatRole(role);
  if (ROLE_KEYS.includes(normalized as RoleKey)) {
    return normalized as RoleKey;
  }
  if (normalized === 'Tenant Admin') return 'Admin';
  if (normalized === 'Inventory Admin') return 'Admin';
  if (normalized === 'Creator') return 'Admin';
  if (normalized === 'Security Analyst') return 'Analyst';
  return 'Viewer';
}

function privilegedRoleBucket(role: string | null | undefined): boolean {
  return roleBucket(role) === 'Admin';
}

function formatTimestamp(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  return date.toLocaleString(undefined, {
    year: 'numeric', month: 'short', day: '2-digit', hour: '2-digit', minute: '2-digit'
  });
}

function formatRelative(value: string | null | undefined): string {
  if (!value) return '—';
  const date = new Date(value);
  if (Number.isNaN(date.getTime())) return value;
  const diffMs = Date.now() - date.getTime();
  if (diffMs < 0) return formatTimestamp(value);
  const minutes = Math.floor(diffMs / 60_000);
  if (minutes < 1) return 'just now';
  if (minutes < 60) return `${minutes} min ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours} hr ago`;
  const days = Math.floor(hours / 24);
  if (days < 30) return `${days} day${days === 1 ? '' : 's'} ago`;
  return formatTimestamp(value);
}

function avatarInitials(member: TenantMember): string {
  const source = (member.displayName || member.email || member.subject || '').trim();
  if (!source) return '?';
  const parts = source.split(/\s+/).filter(Boolean);
  if (parts.length === 1) {
    return parts[0].slice(0, 2).toUpperCase();
  }
  return (parts[0][0] + parts[parts.length - 1][0]).toUpperCase();
}

function memberDisplayName(member: TenantMember): string {
  return member.displayName?.trim() || member.email?.trim() || member.subject || 'Unknown member';
}

function memberSearchHaystack(member: TenantMember): string {
  return [member.displayName, member.email, member.subject, member.role, member.status]
    .filter(Boolean)
    .join(' ');
}

function memberMatchesStructuredFilters(
  member: TenantMember,
  query: string,
  roleFilter: string,
  statusFilter: string
): boolean {
  if (!matchesQuery(memberSearchHaystack(member), query)) return false;
  if (roleFilter !== 'ALL' && member.role !== roleFilter) return false;
  if (statusFilter !== 'ALL' && member.status !== statusFilter) return false;
  return true;
}

function backendRoleForRoleKey(roleKey: RoleKey): string {
  return roleKey === 'Admin' ? 'TENANT_ADMIN'
    : roleKey === 'Analyst' ? 'SECURITY_ANALYST'
    : 'READ_ONLY_AUDITOR';
}

function inviteSearchHaystack(invite: TenantInvite): string {
  return [
    invite.displayName,
    invite.email,
    invite.subject,
    invite.role,
    invite.status,
    invite.invitedByDisplayName,
    invite.invitedBySubject,
  ]
    .filter(Boolean)
    .join(' ');
}

function serviceSearchHaystack(account: ServiceAccount): string {
  return [account.name, account.role, account.status, account.keyId].filter(Boolean).join(' ');
}

function auditSearchHaystack(event: AuditEvent): string {
  return [event.actorSubject, event.action, event.targetType, event.targetId, event.outcome]
    .filter(Boolean)
    .join(' ');
}

function matchesQuery(haystack: string, needle: string): boolean {
  const term = needle.trim().toLowerCase();
  if (!term) return true;
  return haystack.toLowerCase().includes(term);
}

function deriveAuditRisk(event: AuditEvent): 'Low' | 'Medium' | 'High' {
  const outcome = (event.outcome ?? '').toLowerCase();
  const action = (event.action ?? '').toLowerCase();
  if (outcome === 'failure' || outcome === 'denied' || outcome === 'blocked') return 'High';
  if (action.includes('delete') || action.includes('suspend') || action.includes('rotate')) return 'High';
  if (action.includes('update') || action.includes('change') || action.includes('invite') || action.includes('add')) return 'Medium';
  return 'Low';
}

function formatAuditAction(action: string): string {
  return action
    .split('.')
    .map((part) => part.charAt(0).toUpperCase() + part.slice(1))
    .join(' ');
}

const AUDIT_RISK_PILL: Record<'Low' | 'Medium' | 'High', string> = {
  Low: 'severity-pill severity-low',
  Medium: 'severity-pill severity-medium',
  High: 'severity-pill severity-high',
};

function CheckMark({ enabled }: { enabled: boolean }) {
  return (
    <span className={enabled ? 'um-check enabled' : 'um-check'} aria-label={enabled ? 'allowed' : 'not allowed'}>
      {enabled ? 'Yes' : 'No'}
    </span>
  );
}

type IconName = 'plus' | 'mail' | 'key' | 'clock' | 'search' | 'close' | 'download' | 'upload';

function Icon({ name }: { name: IconName }) {
  const paths: Record<IconName, React.ReactNode> = {
    plus: <path d="M12 5v14M5 12h14" />,
    mail: <path d="M4 6h16v12H4zM4 7l8 6 8-6" />,
    key: <path d="M14.5 9.5a4 4 0 1 1-2.1 3.5L21 4.5M18 7.5l2 2" />,
    clock: <path d="M12 6v6l4 2M21 12a9 9 0 1 1-18 0 9 9 0 0 1 18 0Z" />,
    search: <path d="m21 21-4.2-4.2M10.8 18a7.2 7.2 0 1 1 0-14.4 7.2 7.2 0 0 1 0 14.4Z" />,
    close: <path d="M6 6l12 12M6 18 18 6" />,
    download: <path d="M12 4v12m0 0-4-4m4 4 4-4M4 20h16" />,
    upload: <path d="M12 20V8m0 0-4 4m4-4 4 4M4 4h16" />,
  };
  return (
    <svg viewBox="0 0 24 24" aria-hidden="true" className="um-icon">
      {paths[name]}
    </svg>
  );
}

export function UserManagementPage() {
  const params = useParams<{ adminView?: string }>();
  const navigate = useNavigate();
  const activeView = normalizeAdminRouteView(params.adminView);

  const authQuery = useAuthContextQuery();
  const actor = authQuery.data ?? null;
  const tenantId = authQuery.data?.tenantId ?? null;
  const mayAccessTenantAdministration = canManageTenant(actor);
  const mayManageUsers = canManageUsers(actor);
  const mayManageServiceAccounts = canManageServiceAccounts(actor);
  const mayExportAudit = canExportAudit(actor);

  const membersQuery = useTenantMembersQuery(tenantId);
  const invitesQuery = useTenantInvitesQuery(tenantId);
  const serviceAccountsQuery = useServiceAccountsQuery();
  const auditEventsQuery = useAuditEventsQuery();
  const createInvite = useCreateTenantInviteMutation(tenantId);
  const createBulkInvites = useCreateTenantBulkInvitesMutation(tenantId);
  const resendInvite = useResendTenantInviteMutation(tenantId);
  const cancelInvite = useCancelTenantInviteMutation(tenantId);
  const updateMember = useUpdateTenantMemberMutation(tenantId);
  const deleteMember = useDeleteTenantMemberMutation(tenantId);
  const createServiceAccount = useCreateServiceAccountMutation();
  const deactivateServiceAccount = useDeactivateServiceAccountMutation();
  const reactivateServiceAccount = useReactivateServiceAccountMutation();
  const deleteServiceAccount = useDeleteServiceAccountMutation();

  const members = React.useMemo(() => membersQuery.data ?? [], [membersQuery.data]);
  const invites = React.useMemo(() => invitesQuery.data ?? [], [invitesQuery.data]);
  const serviceAccounts = React.useMemo(() => serviceAccountsQuery.data ?? [], [serviceAccountsQuery.data]);
  const auditEvents = React.useMemo(() => auditEventsQuery.data ?? [], [auditEventsQuery.data]);

  const [selectedRole, setSelectedRole] = React.useState<RoleKey>('Admin');
  const [inviteOpen, setInviteOpen] = React.useState(false);
  const [bulkInviteOpen, setBulkInviteOpen] = React.useState(false);
  const [serviceOpen, setServiceOpen] = React.useState(false);
  const [memberQuery, setMemberQuery] = React.useState('');
  const [memberRoleFilter, setMemberRoleFilter] = React.useState('ALL');
  const [memberStatusFilter, setMemberStatusFilter] = React.useState('ALL');
  const [inviteQuery, setInviteQuery] = React.useState('');
  const [serviceQuery, setServiceQuery] = React.useState('');
  const [auditQuery, setAuditQuery] = React.useState('');
  const [exportError, setExportError] = React.useState<string | null>(null);
  const [isExporting, setIsExporting] = React.useState(false);
  const [editingRoleMemberId, setEditingRoleMemberId] = React.useState<string | null>(null);
  const [bulkInviteRows, setBulkInviteRows] = React.useState<ParsedBulkInviteRow[]>([]);
  const [bulkInviteErrors, setBulkInviteErrors] = React.useState<string[]>([]);
  const [bulkInviteFileName, setBulkInviteFileName] = React.useState<string>('');
  const [bulkInviteSummary, setBulkInviteSummary] = React.useState<TenantBulkInviteResponse | null>(null);

  const inviteEmailRef = React.useRef<HTMLInputElement | null>(null);
  const inviteOpenerRef = React.useRef<HTMLButtonElement | null>(null);
  const bulkInviteFileRef = React.useRef<HTMLInputElement | null>(null);
  const bulkInviteOpenerRef = React.useRef<HTMLButtonElement | null>(null);

  const serviceNameRef = React.useRef<HTMLInputElement | null>(null);
  const serviceOpenerRef = React.useRef<HTMLButtonElement | null>(null);

  const setActiveView = React.useCallback(
    (next: AdminRouteView) => {
      if (next !== activeView) {
        navigate(pathForAdminView(next));
      }
    },
    [activeView, navigate]
  );

  const visibleMembers = members.filter((m) => memberMatchesStructuredFilters(m, memberQuery, memberRoleFilter, memberStatusFilter));
  const visibleInvites = invites.filter((invite) => matchesQuery(inviteSearchHaystack(invite), inviteQuery));
  const visibleServiceAccounts = serviceAccounts.filter((a) => matchesQuery(serviceSearchHaystack(a), serviceQuery));
  const visibleAuditEvents = auditEvents.filter((e) => matchesQuery(auditSearchHaystack(e), auditQuery));
  const visibleIdentityAuditEvents = visibleAuditEvents.filter((event) =>
    /(member|invite|service_account|tenant_membership|audit_events)/i.test(event.action)
    || /(tenant_member|tenant_user_invite|service_account)/i.test(event.targetType ?? '')
  );

  const memberCountByRole = React.useMemo(() => {
    const counts: Record<RoleKey, number> = { Admin: 0, Analyst: 0, Viewer: 0 };
    members.forEach((m) => { counts[roleBucket(m.role)] += 1; });
    return counts;
  }, [members]);

  const privilegedCount = members.filter((m) => privilegedRoleBucket(m.role)).length;
  const tenantName = authQuery.data?.tenantName ?? '—';
  const memberRoleOptions = React.useMemo(() => Array.from(new Set(members.map((member) => member.role))).sort(), [members]);
  const memberStatusOptions = React.useMemo(() => Array.from(new Set(members.map((member) => member.status))).sort(), [members]);

  const captionParts: string[] = [];
  if (authQuery.data?.tenantName) captionParts.push(authQuery.data.tenantName);
  captionParts.push(`${members.length} member${members.length === 1 ? '' : 's'}`);
  captionParts.push(`${invites.length} invite${invites.length === 1 ? '' : 's'}`);
  captionParts.push(`${privilegedCount} privileged`);
  captionParts.push(`${serviceAccounts.length} service account${serviceAccounts.length === 1 ? '' : 's'}`);
  captionParts.push(`${auditEvents.length} event${auditEvents.length === 1 ? '' : 's'}`);

  const openInvite = React.useCallback(() => {
    if (!mayManageUsers) return;
    createInvite.reset();
    setInviteOpen(true);
  }, [createInvite, mayManageUsers]);
  const closeInvite = React.useCallback(() => {
    setInviteOpen(false);
  }, []);
  const openBulkInvite = React.useCallback(() => {
    if (!mayManageUsers) return;
    createBulkInvites.reset();
    setBulkInviteErrors([]);
    setBulkInviteRows([]);
    setBulkInviteFileName('');
    setBulkInviteOpen(true);
  }, [createBulkInvites, mayManageUsers]);
  const closeBulkInvite = React.useCallback(() => {
    setBulkInviteOpen(false);
  }, []);
  const openService = React.useCallback(() => {
    if (!mayManageServiceAccounts) return;
    createServiceAccount.reset();
    setServiceOpen(true);
  }, [createServiceAccount, mayManageServiceAccounts]);
  const closeService = React.useCallback(() => {
    setServiceOpen(false);
  }, []);

  React.useEffect(() => {
    if (!inviteOpen) {
      inviteOpenerRef.current?.focus();
      return;
    }
    inviteEmailRef.current?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        closeInvite();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [inviteOpen, closeInvite]);

  React.useEffect(() => {
    if (!bulkInviteOpen) {
      bulkInviteOpenerRef.current?.focus();
      return;
    }
    bulkInviteFileRef.current?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        closeBulkInvite();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [bulkInviteOpen, closeBulkInvite]);

  React.useEffect(() => {
    if (!serviceOpen) {
      serviceOpenerRef.current?.focus();
      return;
    }
    serviceNameRef.current?.focus();
    const handleKey = (event: KeyboardEvent) => {
      if (event.key === 'Escape') {
        event.stopPropagation();
        closeService();
      }
    };
    window.addEventListener('keydown', handleKey);
    return () => window.removeEventListener('keydown', handleKey);
  }, [serviceOpen, closeService]);


  if (!authQuery.isLoading && !mayAccessTenantAdministration) {
    return <Navigate to="/exposure" replace />;
  }

  const handleInviteSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!mayManageUsers) return;
    const formData = new FormData(event.currentTarget);
    const email = String(formData.get('email') ?? '').trim();
    const role = String(formData.get('role') ?? '').trim();
    const displayName = String(formData.get('displayName') ?? '').trim() || email;
    if (!email || !role) return;
    createInvite.mutate(
      { email, displayName, role },
      {
        onSuccess: () => {
          closeInvite();
        },
      }
    );
  };

  const handleBulkInviteFileChange = async (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0];
    if (!file) {
      setBulkInviteRows([]);
      setBulkInviteErrors([]);
      setBulkInviteFileName('');
      return;
    }
    const text = await file.text();
    const parsed = parseTenantInviteCsv(text);
    setBulkInviteFileName(file.name);
    setBulkInviteRows(parsed.rows);
    setBulkInviteErrors(parsed.errors);
  };

  const handleBulkInviteSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!mayManageUsers || bulkInviteRows.length === 0) return;
    createBulkInvites.mutate(
      { invites: bulkInviteRows.map(({ rowNumber: _rowNumber, ...invite }) => invite) },
      {
        onSuccess: (response) => {
          setBulkInviteSummary(response);
          closeBulkInvite();
        },
      }
    );
  };

  const handleServiceSubmit = (event: React.FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    if (!mayManageServiceAccounts) return;
    const formData = new FormData(event.currentTarget);
    const name = String(formData.get('name') ?? '').trim();
    const keyId = String(formData.get('keyId') ?? '').trim();
    const role = String(formData.get('role') ?? '').trim();
    if (!name || !keyId || !role) return;
    createServiceAccount.mutate(
      { name, keyId, role },
      {
        onSuccess: () => {
          closeService();
        },
      }
    );
  };

  const handleExportAudit = async () => {
    if (!mayExportAudit) return;
    setExportError(null);
    setIsExporting(true);
    try {
      const { filename, csv } = await api.exportAuditEventsCsv();
      const blob = new Blob([csv], { type: 'text/csv;charset=utf-8;' });
      const url = URL.createObjectURL(blob);
      const link = document.createElement('a');
      link.href = url;
      link.download = filename;
      document.body.appendChild(link);
      link.click();
      link.remove();
      URL.revokeObjectURL(url);
    } catch (error) {
      setExportError(error instanceof Error ? error.message : 'Export failed');
    } finally {
      setIsExporting(false);
    }
  };

  const membersLoading = membersQuery.isLoading || (!membersQuery.data && membersQuery.isFetching);
  const invitesLoading = invitesQuery.isLoading || (!invitesQuery.data && invitesQuery.isFetching);
  const serviceAccountsLoading = serviceAccountsQuery.isLoading || (!serviceAccountsQuery.data && serviceAccountsQuery.isFetching);
  const auditLoading = auditEventsQuery.isLoading || (!auditEventsQuery.data && auditEventsQuery.isFetching);

  const tenantBlocked = !authQuery.isLoading && !tenantId;

  return (
    <div className="page-grid user-management-page">
      <section className="panel">
        <div className="panel-header">
          <div>
            <h3>User Management</h3>
            <div className="panel-caption">{captionParts.join(' · ')}</div>
          </div>
          <div className="topbar-actions">
            <button
              type="button"
              className="btn btn-secondary btn-sm"
              onClick={() => setActiveView('audit')}
            >
              <Icon name="clock" />
              Audit log
            </button>
            <button
              ref={inviteOpenerRef}
              type="button"
              className="btn btn-primary btn-sm"
              onClick={openInvite}
              disabled={!tenantId}
              hidden={!mayManageUsers}
            >
              <Icon name="plus" />
              Invite user
            </button>
          </div>
        </div>

        {tenantBlocked && (
          <div className="notice error" role="alert">
            <strong>Workspace unavailable.</strong> Could not resolve a tenant from the current session. The
            <code>X-API-Key</code> / <code>X-Tenant-ID</code> credentials may be missing or unauthorized.
          </div>
        )}

        <div className="um-layout">
          <div className="um-content">
            {activeView === 'users' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Members</h3>
                    <p>Tenant membership with role, status, and external subject identity.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={memberQuery}
                        onChange={(event) => setMemberQuery(event.target.value)}
                        placeholder="Search name, email, or subject"
                        aria-label="Search users"
                      />
                    </label>
                    <label className="um-inline-filter">
                      <span>Role</span>
                      <select value={memberRoleFilter} onChange={(event) => setMemberRoleFilter(event.target.value)} aria-label="Filter members by role">
                        <option value="ALL">All roles</option>
                        {memberRoleOptions.map((role) => (
                          <option key={role} value={role}>{formatRole(role)}</option>
                        ))}
                      </select>
                    </label>
                    <label className="um-inline-filter">
                      <span>Status</span>
                      <select value={memberStatusFilter} onChange={(event) => setMemberStatusFilter(event.target.value)} aria-label="Filter members by status">
                        <option value="ALL">All statuses</option>
                        {memberStatusOptions.map((status) => (
                          <option key={status} value={status}>{formatStatus(status)}</option>
                        ))}
                      </select>
                    </label>
                  </div>
                </div>

                {membersQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load members.</strong> {membersQuery.error instanceof Error ? membersQuery.error.message : 'Unknown error'}
                  </div>
                ) : (
                  <div className="um-members-layout">
                    <div className="um-table-scroll">
                      <table className="data-table">
                        <thead>
                          <tr>
                            <th>User</th>
                            <th>Status</th>
                            <th>Role</th>
                            <th>Subject</th>
                            <th>Member since</th>
                            <th aria-label="Actions" />
                          </tr>
                        </thead>
                        <tbody>
                          {membersLoading ? (
                            <tr><td colSpan={6} className="um-empty-cell">Loading members…</td></tr>
                          ) : visibleMembers.length === 0 ? (
                            <tr>
                              <td colSpan={6} className="um-empty-cell">
                                {memberQuery || memberRoleFilter !== 'ALL' || memberStatusFilter !== 'ALL'
                                  ? 'No members match the current filters.'
                                  : 'No active members yet. Invite a user to get started.'}
                              </td>
                            </tr>
                          ) : (
                            visibleMembers.map((member) => (
                              <tr
                                key={member.id}
                              >
                              <td>
                                <div className="um-person">
                                  <span className="um-avatar" aria-hidden="true">{avatarInitials(member)}</span>
                                  <div className="um-person-text">
                                    <strong>{memberDisplayName(member)}</strong>
                                    <small>{member.email ?? '—'}</small>
                                  </div>
                                </div>
                              </td>
                              <td>
                                <span className={statusPillClass(member.status)}>{formatStatus(member.status)}</span>
                              </td>
                              <td>
                                <button
                                  type="button"
                                  className="um-role-button"
                                  onClick={() => {
                                    setSelectedRole(roleBucket(member.role));
                                    setActiveView('roles');
                                  }}
                                  title={`View ${formatRole(member.role)} role detail`}
                                >
                                  {formatRole(member.role)}
                                </button>
                              </td>
                              <td><code>{member.subject}</code></td>
                              <td>{formatTimestamp(member.createdAt)}</td>
                                <td>
                                  <div className="um-card-actions" style={{ justifyContent: 'flex-end' }}>
                                    {editingRoleMemberId === member.id ? (
                                      <select
                                        autoFocus
                                        defaultValue={member.role}
                                        disabled={!mayManageUsers || updateMember.isPending}
                                        style={{ fontSize: 12, padding: '2px 6px', borderRadius: 6, border: '1px solid var(--border)', background: 'var(--panel)', color: 'var(--title)' }}
                                        onChange={(event) => {
                                          event.stopPropagation();
                                          updateMember.mutate({ memberId: member.id, payload: { role: event.target.value } });
                                          setEditingRoleMemberId(null);
                                        }}
                                        onBlur={() => setEditingRoleMemberId(null)}
                                      >
                                        {ROLE_KEYS.map((roleKey) => (
                                          <option key={roleKey} value={backendRoleForRoleKey(roleKey)}>{roleKey}</option>
                                        ))}
                                      </select>
                                    ) : (
                                      <button
                                        type="button"
                                        className="btn btn-ghost btn-sm"
                                        disabled={!mayManageUsers || updateMember.isPending}
                                        onClick={(event) => {
                                          event.stopPropagation();
                                          setEditingRoleMemberId(member.id);
                                        }}
                                      >
                                        Edit Role
                                      </button>
                                    )}
                                    {member.status.toUpperCase() === 'SUSPENDED' ? (
                                      <button
                                        type="button"
                                        className="btn btn-ghost btn-sm"
                                        disabled={!mayManageUsers || updateMember.isPending}
                                        onClick={(event) => {
                                          event.stopPropagation();
                                          updateMember.mutate({ memberId: member.id, payload: { status: 'ACTIVE' } });
                                        }}
                                      >
                                        Reactivate
                                      </button>
                                    ) : (
                                      <button
                                        type="button"
                                        className="btn btn-ghost btn-sm"
                                        disabled={!mayManageUsers || updateMember.isPending}
                                        onClick={(event) => {
                                          event.stopPropagation();
                                          updateMember.mutate({ memberId: member.id, payload: { status: 'SUSPENDED' } });
                                        }}
                                      >
                                        Suspend
                                      </button>
                                    )}
                                    <button
                                      type="button"
                                      className="btn btn-ghost btn-sm"
                                      disabled={!mayManageUsers || deleteMember.isPending}
                                      onClick={(event) => {
                                        event.stopPropagation();
                                        deleteMember.mutate(member.id);
                                      }}
                                    >
                                      Remove
                                    </button>
                                  </div>
                                </td>
                              </tr>
                            ))
                          )}
                        </tbody>
                      </table>
                    </div>
                  </div>
                )}
              </>
            )}

            {activeView === 'invites' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Pending Invitations</h3>
                    <p>Email invitations awaiting acceptance and password setup.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={inviteQuery}
                        onChange={(event) => setInviteQuery(event.target.value)}
                        placeholder="Search invites"
                        aria-label="Search invites"
                      />
                    </label>
                    <button type="button" className="btn btn-primary btn-sm" onClick={openInvite} disabled={!tenantId || !mayManageUsers} hidden={!mayManageUsers}>
                      <Icon name="mail" />
                      New invite
                    </button>
                    <button
                      ref={bulkInviteOpenerRef}
                      type="button"
                      className="btn btn-secondary btn-sm"
                      onClick={openBulkInvite}
                      disabled={!tenantId || !mayManageUsers}
                      hidden={!mayManageUsers}
                    >
                      <Icon name="upload" />
                      Import CSV
                    </button>
                    {!mayManageUsers && (
                      <span className="panel-caption">Invitations are read-only for your role.</span>
                    )}
                  </div>
                </div>

                {bulkInviteSummary && (
                  <div className={bulkInviteSummary.failedCount > 0 ? 'notice' : 'notice success'} role="status">
                    <strong>Bulk import complete.</strong> {bulkInviteSummary.invitedCount} of {bulkInviteSummary.requestedCount} invites sent.
                    {bulkInviteSummary.failedCount > 0 && ` ${bulkInviteSummary.failedCount} row${bulkInviteSummary.failedCount === 1 ? '' : 's'} need attention.`}
                  </div>
                )}

                {invitesQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load invites.</strong> {invitesQuery.error instanceof Error ? invitesQuery.error.message : 'Unknown error'}
                  </div>
                ) : invitesLoading ? (
                  <div className="um-empty-block">Loading invites…</div>
                ) : visibleInvites.length === 0 ? (
                  <div className="um-empty-block">
                    {inviteQuery
                      ? <>No invites match &ldquo;{inviteQuery}&rdquo;.</>
                      : 'No pending invitations. New invites appear here until the user accepts and sets a password.'}
                  </div>
                ) : (
                  <div className="um-card-grid">
                    {visibleInvites.map((invite) => (
                      <article key={invite.id} className="um-card">
                        <div className="um-card-title">
                          <span className="um-card-icon"><Icon name="mail" /></span>
                          <div style={{ minWidth: 0 }}>
                            <h4>{invite.displayName || invite.email}</h4>
                            <p>{invite.email}</p>
                          </div>
                        </div>
                        <div className="um-card-row"><span>Role</span><strong>{formatRole(invite.role)}</strong></div>
                        <div className="um-card-row">
                          <span>Status</span>
                          <strong><span className={statusPillClass(invite.status)}>{formatStatus(invite.status)}</span></strong>
                        </div>
                        <div className="um-card-row"><span>Invited</span><strong>{formatRelative(invite.createdAt)}</strong></div>
                        <div className="um-card-row"><span>Expires</span><strong>{formatTimestamp(invite.expiresAt)}</strong></div>
                        <div className="um-card-row"><span>Invited by</span><strong>{invite.invitedByDisplayName || invite.invitedBySubject || '—'}</strong></div>
                        {invite.deliveryDetail ? (
                          <div className="um-card-row"><span>Delivery</span><strong>{invite.deliveryDetail}</strong></div>
                        ) : null}
                        <div className="um-card-actions">
                          <button
                            type="button"
                            className="btn btn-secondary btn-sm"
                            disabled={!mayManageUsers || resendInvite.isPending}
                            onClick={() => resendInvite.mutate(invite.id)}
                          >
                            Resend
                          </button>
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            disabled={!mayManageUsers || cancelInvite.isPending}
                            onClick={() => cancelInvite.mutate(invite.id)}
                          >
                            Cancel
                          </button>
                        </div>
                      </article>
                    ))}
                  </div>
                )}

                {bulkInviteSummary && bulkInviteSummary.results.length > 0 && (
                  <div className="um-table-scroll" style={{ marginTop: '1rem' }}>
                    <table className="data-table">
                      <thead>
                        <tr>
                          <th>Email</th>
                          <th>Role</th>
                          <th>Status</th>
                          <th>Message</th>
                        </tr>
                      </thead>
                      <tbody>
                        {bulkInviteSummary.results.map((result) => (
                          <tr key={`${result.email}-${result.status}`}>
                            <td>{result.email}</td>
                            <td>{formatRole(result.role ?? '')}</td>
                            <td><span className={statusPillClass(result.status)}>{formatStatus(result.status)}</span></td>
                            <td>{result.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </>
            )}

            {activeView === 'roles' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Role Model</h3>
                    <p>Permission clarity for least-privilege review. Member counts are live.</p>
                  </div>
                </div>

                <div className="notice" role="note">
                  <strong>Illustrative.</strong> This tenant-facing matrix is simplified for V1 customer validation.
                  The current implementation maps to existing backend authorities such as
                  <code>ROLE_TENANT_ADMIN</code>, <code>ROLE_SECURITY_ANALYST</code>, and
                  <code>ROLE_READ_ONLY_AUDITOR</code>. Founder-only platform roles stay out of this workspace.
                </div>

                <div className="um-role-grid">
                  {ROLE_KEYS.map((roleKey) => (
                    <button
                      key={roleKey}
                      type="button"
                      className={selectedRole === roleKey ? 'um-role-card active' : 'um-role-card'}
                      aria-pressed={selectedRole === roleKey}
                      onClick={() => setSelectedRole(roleKey)}
                    >
                      <strong>{roleKey}</strong>
                      <span>{memberCountByRole[roleKey]} members</span>
                      <small>{ROLE_DESCRIPTIONS[roleKey]}</small>
                    </button>
                  ))}
                </div>

                <div className="um-table-scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Capability</th>
                        <th>Admin</th>
                        <th>Analyst</th>
                        <th>Viewer</th>
                      </tr>
                    </thead>
                    <tbody>
                      {ROLE_MATRIX.map((row) => (
                        <tr key={row.capability}>
                          <td>{row.capability}</td>
                          <td><CheckMark enabled={row.admin} /></td>
                          <td><CheckMark enabled={row.analyst} /></td>
                          <td><CheckMark enabled={row.viewer} /></td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </>
            )}

            {activeView === 'service-accounts' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Service Accounts</h3>
                    <p>Machine identities with role, key id, status, and last-used timestamp.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={serviceQuery}
                        onChange={(event) => setServiceQuery(event.target.value)}
                        placeholder="Search service accounts"
                        aria-label="Search service accounts"
                      />
                    </label>
                    <button
                      ref={serviceOpenerRef}
                      type="button"
                      className="btn btn-primary btn-sm"
                      onClick={openService}
                      disabled={!mayManageServiceAccounts}
                      hidden={!mayManageServiceAccounts}
                    >
                      <Icon name="key" />
                      Create account
                    </button>
                  </div>
                </div>

                {serviceAccountsQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load service accounts.</strong> {serviceAccountsQuery.error instanceof Error ? serviceAccountsQuery.error.message : 'Unknown error'}
                  </div>
                ) : serviceAccountsLoading ? (
                  <div className="um-empty-block">Loading service accounts…</div>
                ) : visibleServiceAccounts.length === 0 ? (
                  <div className="um-empty-block">
                    {serviceQuery
                      ? <>No service accounts match &ldquo;{serviceQuery}&rdquo;.</>
                      : 'No service accounts yet. Create one to issue a machine identity.'}
                  </div>
                ) : (
                  <div className="um-card-grid">
                    {visibleServiceAccounts.map((account) => (
                      <article key={account.id} className="um-card">
                        <div className="um-card-title">
                          <span className="um-card-icon"><Icon name="key" /></span>
                          <div style={{ minWidth: 0, flex: 1 }}>
                            <h4>{account.name}</h4>
                            <p><code>{account.keyId}</code></p>
                          </div>
                          <span className={statusPillClass(account.status)}>{formatStatus(account.status)}</span>
                        </div>
                        <div className="um-card-row"><span>Role</span><strong>{formatRole(account.role)}</strong></div>
                        <div className="um-card-row"><span>Created</span><strong>{formatRelative(account.createdAt)}</strong></div>
                        <div className="um-card-row"><span>Last used</span><strong>{account.lastUsedAt ? formatRelative(account.lastUsedAt) : 'Never'}</strong></div>
                        <div className="um-card-actions">
                          {account.status.toUpperCase() === 'ACTIVE' && (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={!mayManageServiceAccounts || deactivateServiceAccount.isPending}
                              onClick={() => deactivateServiceAccount.mutate(account.id)}
                            >
                              Deactivate
                            </button>
                          )}
                          {account.status.toUpperCase() !== 'ACTIVE' && (
                            <button
                              type="button"
                              className="btn btn-secondary btn-sm"
                              disabled={!mayManageServiceAccounts || reactivateServiceAccount.isPending}
                              onClick={() => reactivateServiceAccount.mutate(account.id)}
                            >
                              Reactivate
                            </button>
                          )}
                          <button
                            type="button"
                            className="btn btn-ghost btn-sm"
                            disabled={!mayManageServiceAccounts || deleteServiceAccount.isPending}
                            onClick={() => deleteServiceAccount.mutate(account.id)}
                          >
                            Delete
                          </button>
                        </div>
                      </article>
                    ))}
                  </div>
                )}
              </>
            )}

            {activeView === 'audit' && (
              <>
                <div className="um-section-head">
                  <div>
                    <h3>Audit Events</h3>
                    <p>Latest 100 identity and access events from the tenant audit stream.</p>
                  </div>
                  <div className="um-section-head-actions">
                    <label className="um-search">
                      <Icon name="search" />
                      <input
                        value={auditQuery}
                        onChange={(event) => setAuditQuery(event.target.value)}
                        placeholder="Search events"
                        aria-label="Search audit events"
                      />
                    </label>
                    <button type="button" className="btn btn-secondary btn-sm" onClick={handleExportAudit} disabled={isExporting || !mayExportAudit}>
                      <Icon name="download" />
                      {isExporting ? 'Exporting…' : 'Export CSV'}
                    </button>
                  </div>
                </div>

                {exportError && (
                  <div className="notice error" role="alert">
                    <strong>Export failed.</strong> {exportError}
                  </div>
                )}

                {auditEventsQuery.isError ? (
                  <div className="notice error" role="alert">
                    <strong>Failed to load audit events.</strong> {auditEventsQuery.error instanceof Error ? auditEventsQuery.error.message : 'Unknown error'}
                  </div>
                ) : auditLoading ? (
                  <div className="um-empty-block">Loading events…</div>
                ) : visibleIdentityAuditEvents.length === 0 ? (
                  <div className="um-empty-block">
                    {auditQuery
                      ? <>No events match &ldquo;{auditQuery}&rdquo;.</>
                      : 'No identity audit events recorded yet.'}
                  </div>
                ) : (
                  <div className="um-timeline">
                    {visibleIdentityAuditEvents.map((event) => {
                      const risk = deriveAuditRisk(event);
                      return (
                        <article key={event.id} className="um-audit-row">
                          <span className={AUDIT_RISK_PILL[risk]}>{risk}</span>
                          <div className="um-audit-meta">
                            <strong>{formatAuditAction(event.action)}</strong>
                            <span>
                              {event.actorSubject ?? 'system'}
                              {event.targetType && ` · ${event.targetType}${event.targetId ? `:${event.targetId.slice(0, 8)}` : ''}`}
                              {event.outcome && ` · ${event.outcome}`}
                            </span>
                          </div>
                          <time dateTime={event.occurredAt}>{formatRelative(event.occurredAt)}</time>
                        </article>
                      );
                    })}
                  </div>
                )}
              </>
            )}
          </div>
        </div>
      </section>

      {inviteOpen && (
        <div className="um-modal-backdrop" role="presentation" onClick={closeInvite}>
          <section
            className="um-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="invite-user-title"
            onClick={(event) => event.stopPropagation()}
          >
            <form onSubmit={handleInviteSubmit} style={{ display: 'contents' }}>
              <div className="um-modal-head">
                <div>
                  <h3 id="invite-user-title">Invite User</h3>
                  <p>Sends a time-bound email invite. After acceptance, the user sets a password and becomes an active tenant member.</p>
                </div>
                <button
                  type="button"
                  className="um-icon-button"
                  aria-label="Close invite dialog"
                  onClick={closeInvite}
                >
                  <Icon name="close" />
                </button>
              </div>
              {createInvite.isError && (
                <div className="notice error" role="alert">
                  <strong>Could not send invite.</strong> {createInvite.error instanceof Error ? createInvite.error.message : 'Unknown error'}
                </div>
              )}
              <div className="um-form-grid">
                <label>
                  Email
                  <input
                    ref={inviteEmailRef}
                    name="email"
                    type="email"
                    placeholder="name@example.com"
                    required
                    autoComplete="email"
                  />
                </label>
                <label>
                  Display name
                  <input
                    name="displayName"
                    type="text"
                    placeholder="Name (optional)"
                    autoComplete="name"
                  />
                </label>
                <label>
                  Role
                  <select name="role" defaultValue="SECURITY_ANALYST" required>
                    {ROLE_KEYS.map((roleKey) => (
                      <option
                        key={roleKey}
                        value={backendRoleForRoleKey(roleKey)}
                      >
                        {roleKey}
                      </option>
                    ))}
                  </select>
                </label>
                <label>
                  Tenant
                  <input value={tenantName} disabled readOnly />
                </label>
              </div>
              <div className="um-modal-actions">
                <button type="button" className="btn btn-secondary btn-sm" onClick={closeInvite}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={createInvite.isPending || !tenantId}>
                  {createInvite.isPending ? 'Sending…' : 'Send invite'}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}

      {bulkInviteOpen && (
        <div className="um-modal-backdrop" role="presentation" onClick={closeBulkInvite}>
          <section
            className="um-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="bulk-invite-title"
            onClick={(event) => event.stopPropagation()}
          >
            <form onSubmit={handleBulkInviteSubmit} style={{ display: 'contents' }}>
              <div className="um-modal-head">
                <div>
                  <h3 id="bulk-invite-title">Import Users from CSV</h3>
                  <p>Upload a CSV with <code>email</code>, optional <code>displayName</code>, and optional <code>role</code>. Supported role labels: Admin, Analyst, Viewer.</p>
                </div>
                <button
                  type="button"
                  className="um-icon-button"
                  aria-label="Close bulk invite dialog"
                  onClick={closeBulkInvite}
                >
                  <Icon name="close" />
                </button>
              </div>
              {createBulkInvites.isError && (
                <div className="notice error" role="alert">
                  <strong>Could not import users.</strong> {createBulkInvites.error instanceof Error ? createBulkInvites.error.message : 'Unknown error'}
                </div>
              )}
              <div className="um-form-grid">
                <label className="um-detail-full">
                  CSV file
                  <input
                    ref={bulkInviteFileRef}
                    name="bulkInviteFile"
                    type="file"
                    accept=".csv,text/csv"
                    onChange={handleBulkInviteFileChange}
                  />
                </label>
                <label>
                  Template columns
                  <input value="email,displayName,role" disabled readOnly />
                </label>
                <label>
                  Tenant
                  <input value={tenantName} disabled readOnly />
                </label>
              </div>
              {bulkInviteFileName && (
                <div className="notice" role="status">
                  <strong>{bulkInviteFileName}</strong> parsed with {bulkInviteRows.length} valid row{bulkInviteRows.length === 1 ? '' : 's'}.
                </div>
              )}
              {bulkInviteErrors.length > 0 && (
                <div className="notice error" role="alert">
                  <strong>CSV validation issues.</strong> {bulkInviteErrors.join(' ')}
                </div>
              )}
              {bulkInviteRows.length > 0 && (
                <div className="um-table-scroll">
                  <table className="data-table">
                    <thead>
                      <tr>
                        <th>Row</th>
                        <th>Email</th>
                        <th>Display name</th>
                        <th>Role</th>
                      </tr>
                    </thead>
                    <tbody>
                      {bulkInviteRows.slice(0, 25).map((row) => (
                        <tr key={`${row.rowNumber}-${row.email}`}>
                          <td>{row.rowNumber}</td>
                          <td>{row.email}</td>
                          <td>{row.displayName}</td>
                          <td>{formatRole(row.role)}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {bulkInviteRows.length > 25 && (
                    <p className="panel-caption">Showing first 25 rows of {bulkInviteRows.length} parsed invites.</p>
                  )}
                </div>
              )}
              <div className="um-modal-actions">
                <button type="button" className="btn btn-secondary btn-sm" onClick={closeBulkInvite}>Cancel</button>
                <button
                  type="submit"
                  className="btn btn-primary btn-sm"
                  disabled={createBulkInvites.isPending || !tenantId || bulkInviteRows.length === 0 || bulkInviteErrors.length > 0}
                >
                  {createBulkInvites.isPending ? 'Importing…' : `Send ${bulkInviteRows.length || ''} invite${bulkInviteRows.length === 1 ? '' : 's'}`.trim()}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}

      {serviceOpen && (
        <div className="um-modal-backdrop" role="presentation" onClick={closeService}>
          <section
            className="um-modal"
            role="dialog"
            aria-modal="true"
            aria-labelledby="service-account-title"
            onClick={(event) => event.stopPropagation()}
          >
            <form onSubmit={handleServiceSubmit} style={{ display: 'contents' }}>
              <div className="um-modal-head">
                <div>
                  <h3 id="service-account-title">Create Service Account</h3>
                  <p>Issues a machine identity scoped to the current tenant. The Key ID is the credential the integration presents.</p>
                </div>
                <button
                  type="button"
                  className="um-icon-button"
                  aria-label="Close service account dialog"
                  onClick={closeService}
                >
                  <Icon name="close" />
                </button>
              </div>
              {createServiceAccount.isError && (
                <div className="notice error" role="alert">
                  <strong>Could not create service account.</strong> {createServiceAccount.error instanceof Error ? createServiceAccount.error.message : 'Unknown error'}
                </div>
              )}
              <div className="um-form-grid">
                <label>
                  Name
                  <input
                    ref={serviceNameRef}
                    name="name"
                    type="text"
                    placeholder="github-sbom-ingest"
                    required
                  />
                </label>
                <label>
                  Key ID
                  <input
                    name="keyId"
                    type="text"
                    placeholder="key-abc123"
                    required
                  />
                </label>
                <label>
                  Role
                  <select name="role" defaultValue="INTEGRATION_WRITER" required>
                    <option value="INTEGRATION_WRITER">Integration Writer</option>
                    <option value="WORKFLOW_WRITER">Workflow Writer</option>
                    <option value="AUDIT_EXPORTER">Audit Exporter</option>
                    <option value="VIEWER">Viewer</option>
                  </select>
                </label>
                <label>
                  Tenant
                  <input value={tenantName} disabled readOnly />
                </label>
              </div>
              <div className="um-modal-actions">
                <button type="button" className="btn btn-secondary btn-sm" onClick={closeService}>Cancel</button>
                <button type="submit" className="btn btn-primary btn-sm" disabled={createServiceAccount.isPending}>
                  {createServiceAccount.isPending ? 'Creating…' : 'Create account'}
                </button>
              </div>
            </form>
          </section>
        </div>
      )}
    </div>
  );
}
