export type OwnerStatus = '' | 'OWNED' | 'UNOWNED' | 'CONFLICT';
export type OwnerFilterValue = { ownerTeamId: string; ownershipStatus: OwnerStatus };

export const EMPTY_OWNER_FILTER: OwnerFilterValue = { ownerTeamId: '', ownershipStatus: '' };
