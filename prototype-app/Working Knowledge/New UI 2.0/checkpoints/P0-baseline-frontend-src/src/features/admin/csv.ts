import type { TenantInviteRequest } from './types';

export type ParsedBulkInviteRow = TenantInviteRequest & {
  rowNumber: number;
};

export type ParsedBulkInviteResult = {
  rows: ParsedBulkInviteRow[];
  errors: string[];
};

const ROLE_ALIASES: Record<string, TenantInviteRequest['role']> = {
  ADMIN: 'TENANT_ADMIN',
  TENANT_ADMIN: 'TENANT_ADMIN',
  'SECURITY LEAD': 'SECURITY_ANALYST',
  SECURITY_LEAD: 'SECURITY_ANALYST',
  SECURITY_ANALYST: 'SECURITY_ANALYST',
  ANALYST: 'SECURITY_ANALYST',
  VIEWER: 'READ_ONLY_AUDITOR',
  READ_ONLY_AUDITOR: 'READ_ONLY_AUDITOR',
  AUDITOR: 'READ_ONLY_AUDITOR',
};

function normalizeHeader(value: string): string {
  return value.trim().toLowerCase().replace(/[^a-z0-9]+/g, '');
}

function parseCsvLine(line: string): string[] {
  const cells: string[] = [];
  let current = '';
  let inQuotes = false;

  for (let index = 0; index < line.length; index += 1) {
    const char = line[index];
    if (char === '"') {
      if (inQuotes && line[index + 1] === '"') {
        current += '"';
        index += 1;
      } else {
        inQuotes = !inQuotes;
      }
      continue;
    }
    if (char === ',' && !inQuotes) {
      cells.push(current);
      current = '';
      continue;
    }
    current += char;
  }

  cells.push(current);
  return cells.map((cell) => cell.trim());
}

function resolveRole(value: string | undefined): TenantInviteRequest['role'] {
  const normalized = (value ?? '').trim();
  if (!normalized) {
    return 'SECURITY_ANALYST';
  }
  const key = normalized.toUpperCase().replace(/[^A-Z0-9]+/g, '_');
  return ROLE_ALIASES[key] ?? 'SECURITY_ANALYST';
}

export function parseTenantInviteCsv(csvText: string): ParsedBulkInviteResult {
  const trimmed = csvText.trim();
  if (!trimmed) {
    return { rows: [], errors: ['CSV file is empty.'] };
  }

  const lines = trimmed
    .split(/\r?\n/)
    .map((line) => line.trim())
    .filter((line) => line.length > 0);
  if (lines.length === 0) {
    return { rows: [], errors: ['CSV file is empty.'] };
  }

  const headers = parseCsvLine(lines[0]).map(normalizeHeader);
  const emailIndex = headers.findIndex((header) => header === 'email');
  const displayNameIndex = headers.findIndex((header) => header === 'displayname' || header === 'name' || header === 'fullname');
  const roleIndex = headers.findIndex((header) => header === 'role');

  if (emailIndex < 0) {
    return { rows: [], errors: ['CSV must include an email column.'] };
  }

  const rows: ParsedBulkInviteRow[] = [];
  const errors: string[] = [];
  const seenEmails = new Set<string>();

  for (let index = 1; index < lines.length; index += 1) {
    const cells = parseCsvLine(lines[index]);
    const rowNumber = index + 1;
    const email = (cells[emailIndex] ?? '').trim().toLowerCase();
    const displayName = displayNameIndex >= 0 ? (cells[displayNameIndex] ?? '').trim() : '';
    const role = resolveRole(roleIndex >= 0 ? cells[roleIndex] : undefined);

    if (!email) {
      errors.push(`Row ${rowNumber}: email is required.`);
      continue;
    }
    if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      errors.push(`Row ${rowNumber}: invalid email "${email}".`);
      continue;
    }
    if (seenEmails.has(email)) {
      errors.push(`Row ${rowNumber}: duplicate email "${email}" in this file.`);
      continue;
    }
    seenEmails.add(email);
    rows.push({
      rowNumber,
      email,
      displayName: displayName || email,
      role,
    });
  }

  return { rows, errors };
}
