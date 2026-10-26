export type OwnershipAuthority =
  | 'NONE'
  | 'LEGACY'
  | 'SOURCE_DERIVED'
  | 'SOURCE_PROVIDED'
  | 'CMDB'
  | string;

export type OwnershipSummary = {
  displayName: string;
  ownerTeam?: string;
  ownerEmail?: string;
  managedBy?: string;
  department?: string;
  supportGroup?: string;
  assignedTo?: string;
  sourceSystem?: string;
  sourceType?: string;
  authority?: OwnershipAuthority;
  updatedAt?: string;
};
