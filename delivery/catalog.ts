import catalogSource from "./projects.json";

export type Project = { name: string; repositoryId: string; project: string; number: string; region: string; registry: string; service: string; data: boolean; env: Record<string, string>; secrets: Record<string, string>; repository?: string; sourceDirectory?: string; identity?: boolean };
const catalog = catalogSource as unknown as { schemaVersion: number; owner: string; platformRepositoryId: string; projects: Project[] };
export const owner = "collinbentley1";
export const platformRepositoryId = "1255856466";
export const projects: readonly Project[] = catalog.projects;

export function validateCatalog(value: { schemaVersion: number; owner: string; platformRepositoryId: string; projects: Project[] }): void {
  if (value.schemaVersion !== 1 || value.owner !== owner || value.platformRepositoryId !== platformRepositoryId) throw new Error("Invalid catalog authority.");
  const names = new Set<string>(); const ids = new Set<string>();
  for (const app of value.projects) {
    if (!/^[a-z][a-z0-9-]{0,39}$/.test(app.name) || !/^[1-9][0-9]*$/.test(app.repositoryId) || !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(app.project) || !/^[1-9][0-9]*$/.test(app.number) || app.region !== "us-east4" || !/^[a-z][a-z0-9-]{0,39}$/.test(app.service) || !/^[a-z][a-z0-9-]{0,39}$/.test(app.registry)) throw new Error("Invalid project identity.");
    if (names.has(app.name) || ids.has(app.repositoryId)) throw new Error("Duplicate project identity.");
    names.add(app.name); ids.add(app.repositoryId);
    if (app.sourceDirectory !== undefined && (app.repository !== "platform" || app.repositoryId !== platformRepositoryId || app.sourceDirectory !== "templates/app")) throw new Error("Invalid reference source.");
    for (const [key, val] of Object.entries(app.env)) if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof val !== "string" || val.length > 8192) throw new Error("Invalid runtime configuration.");
    for (const [key, val] of Object.entries(app.secrets)) if (!/^[A-Z][A-Z0-9_]*$/.test(key) || typeof val !== "string" || !/^[a-z][a-z0-9-]*:[1-9][0-9]*$/.test(val)) throw new Error("Runtime secrets require exact numeric versions.");
  }
}
validateCatalog(catalog);

export function project(name: string): Project {
  const selected = projects.find(app => app.name === name);
  if (!selected) throw new Error("Project is not registered.");
  return selected;
}
export function imageName(app: Project): string { return `${app.region}-docker.pkg.dev/${app.project}/${app.registry}/${app.service}`; }
export function identity(app: Project, purpose: "publish" | "deploy"): string { return `platform-${purpose}@${app.project}.iam.gserviceaccount.com`; }
export function provider(app: Project): string { return `projects/${app.number}/locations/global/workloadIdentityPools/platform-delivery/providers/github`; }
