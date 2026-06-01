import { readFile } from "node:fs/promises";
import { join } from "node:path";

const root = join(import.meta.dir, "..");
const failures: string[] = [];
const reusableWorkflows = [
  "application.yml",
  "socket-firewall.yml",
  "infrastructure.yml",
  "deploy-prod.yml",
  "deploy-preview.yml",
  "cleanup-preview.yml",
];

for (const workflow of reusableWorkflows) {
  const path = `.github/workflows/${workflow}`;
  const text = await read(path);
  requireContains(path, text, "workflow_call:", "Reusable workflow must expose workflow_call.");
  rejectContains(path, text, "@v", "Actions must be pinned to immutable SHAs, not mutable version tags.");
}

const readme = await read("README.md");
requireContains("README.md", readme, "v0.1.2", "README should document the current release pin.");

const moduleMain = await read("terraform/modules/cloud-run-service/main.tf");
const moduleVersions = await read("terraform/modules/cloud-run-service/versions.tf");
requireContains(
  "terraform/modules/cloud-run-service/versions.tf",
  moduleVersions,
  "google.no_attribution",
  "Domain mappings must support the no-attribution provider alias.",
);
requireContains(
  "terraform/modules/cloud-run-service/main.tf",
  moduleMain,
  "template[0].containers[0].env",
  "Cloud Run service must ignore deploy-owned runtime environment drift.",
);

if (failures.length > 0) {
  console.error(failures.join("\n"));
  process.exit(1);
}

async function read(path: string): Promise<string> {
  return await readFile(join(root, path), "utf8");
}

function requireContains(path: string, text: string, needle: string, message: string): void {
  if (!text.includes(needle)) {
    failures.push(`${path}: ${message}`);
  }
}

function rejectContains(path: string, text: string, needle: string, message: string): void {
  if (text.includes(needle)) {
    failures.push(`${path}: ${message}`);
  }
}
