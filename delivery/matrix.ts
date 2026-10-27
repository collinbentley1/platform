import { projects } from "./catalog.ts";
import { output } from "./github.ts";

// Infrastructure, delivery and upgrades all use the same reviewed catalog.
export const applications = () => ({ include: projects.map(app => ({ application: app.name, project: app.project, number: app.number })) });
if (import.meta.main) {
  const repositories = projects.filter(app => !app.sourceDirectory).map(app => app.repository ?? app.name);
  const selected = Bun.env.PLATFORM_REPOSITORY;
  if (selected && !repositories.includes(selected)) throw new Error("Repository is not a registered consumer.");
  await output({ applications: JSON.stringify(applications()), repositories: JSON.stringify(selected ? [selected] : repositories) });
}
