import {readdir,readFile,lstat} from "node:fs/promises";
import {join,resolve} from "node:path";
import {projects,validateCatalog} from "../delivery/catalog.ts";
const root=resolve(import.meta.dir,"..");
for(const file of await readdir(join(root,".github/workflows"))) {
  if(!file.endsWith(".yml")) continue;
  const path=join(root,".github/workflows",file);
  if(!(await lstat(path)).isFile()) throw new Error("Workflow must be a regular file.");
  const source=await readFile(path,"utf8");
  for(const match of source.matchAll(/uses:\s*([^\s]+)/g)) if(!/^[A-Za-z0-9_.\/-]+@[a-f0-9]{40}$/.test(match[1]!)) throw new Error(`Action is not immutable: ${file}`);
  if(!source.includes("permissions: {}")) throw new Error(`Workflow needs explicit permissions: ${file}`);
  if(source.includes("secrets: inherit")) throw new Error("Application code may not inherit platform secrets.");
}
const docker=await readFile(join(root,"delivery/Dockerfile"),"utf8");
const stages = new Set<string>();
for(const line of docker.split("\n").filter(line=>line.startsWith("FROM "))) {
  const match = /^FROM (?:--platform=\$BUILDPLATFORM )?([^\s]+)(?: AS ([a-z-]+))?$/.exec(line);
  if(!match || (!stages.has(match[1]!) && !/@sha256:[a-f0-9]{64}$/.test(match[1]!))) throw new Error("Container bases must be digest-pinned.");
  if(match[2]) stages.add(match[2]);
}
if(!docker.includes("USER 1000:1000")) throw new Error("Runtime must run without root.");
console.log(`Verified platform policy for ${projects.length} applications.`);
