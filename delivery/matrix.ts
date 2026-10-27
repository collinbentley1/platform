import { projects } from "./catalog.ts";
import { output } from "./github.ts";

// Infrastructure, delivery and upgrades all use the same reviewed catalog.
export const applications = () => ({ include: projects.map(app => ({ application: app.name, project: app.project, number: app.number })) });
if (import.meta.main) await output({ applications: JSON.stringify(applications()), repositories: JSON.stringify(projects.filter(app => !app.sourceDirectory).map(app => app.repository ?? app.name)) });
