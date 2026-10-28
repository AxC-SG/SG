/** The exact grant commands for one project, so the customer never has to compose them. */
export function grantCommands(serviceAccountEmail: string, projectId: string, roles: string[]): string {
  return roles
    .map((role) => `gcloud projects add-iam-policy-binding ${projectId} --member="serviceAccount:${serviceAccountEmail}" --role="${role}"`)
    .join('\n');
}
