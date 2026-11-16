import { ApiError } from '../../api/client';

/** Plain wording for the two expected refusals; anything else keeps the server's message. */
export function occurrenceErrorText(error: unknown): string {
  if (error instanceof ApiError && error.status === 404) return 'This row has no registered occurrence yet, so an owner cannot be assigned. Try again after the next ownership refresh.';
  if (error instanceof ApiError && error.status === 409) return 'Assigning owners to BOM occurrences is available once BOM ownership is canonical.';
  return error instanceof Error ? error.message : 'The request failed.';
}
