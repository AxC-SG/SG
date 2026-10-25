export type AllowedTenant = {
  id: string;
  name: string;
  slug: string | null;
  role: string;
  accessMode?: string | null;
  accessReferenceId?: string | null;
  expiresAt?: string | null;
  revocable?: boolean;
};

export type ActorContext = {
  creator: boolean;
  principal: string;
  userId: string;
  tenantId: string | null;
  tenantName: string | null;
  roles: string[];
  allowedTenants?: AllowedTenant[];
  platformScope?: boolean;
  actingAsPlatformOwner?: boolean;
  tenantAccessMode?: string | null;
  tenantAccessReferenceId?: string | null;
  sensitiveActionConfirmationRequired?: boolean;
  supportAccessMode?: string | null;
  supportGrantExpiresAt?: string | null;
  planCode?: string | null;
  demo?: boolean | null;
  demoExpiresAt?: string | null;
  demoDaysRemaining?: number | null;
  demoCapabilities?: Record<string, boolean> | null;
  demoUsage?: Record<string, number> | null;
  // Effective entitlement snapshot from /api/auth/context. Optional for fixture compatibility;
  // the production API always returns it. Absent/false means the feature is disabled (fail closed).
  entitlements?: Record<string, boolean> | null;
};
