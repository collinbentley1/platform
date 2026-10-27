import { projects } from "./catalog.ts";
import { deploy, service } from "./deploy.ts";
import { output } from "./github.ts";
import { requireSha } from "./consumer.ts";
import type { ImageEvidence } from "./oci.ts";
const app = projects.find(app => app.name === Bun.env.PLATFORM_APP);
if (!app) throw new Error("Unknown application.");
if (Bun.argv[2] === "audience") await output({ audience: (await service(app, true)).uri });
else if (Bun.argv[2] === "deploy") {
  const evidence = await Bun.file(Bun.argv[3]!).json() as ImageEvidence;
  if (evidence.schemaVersion !== 1 || evidence.sourceSha !== requireSha(Bun.env.SOURCE_SHA ?? "") || evidence.platformSha !== requireSha(Bun.env.RELEASE_SHA ?? "") || ![evidence.digest,evidence.runnableDigest].every(d => /^sha256:[a-f0-9]{64}$/.test(d))) throw new Error("Deployment evidence differs from the selected source.");
  console.log(JSON.stringify(await deploy(app, evidence, Bun.env.PLATFORM_PR || undefined)));
} else throw new Error("Expected audience or deploy.");
