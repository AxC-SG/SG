/** Message for a failed ownership request; the API's own text when it sent one. */
export function ownershipErrorText(error: unknown, fallback: string): string {
  return error instanceof Error && error.message ? error.message : fallback;
}
