import { readFile } from "node:fs/promises";
import { join } from "node:path";
import { type DenyFlags, denyMatrix } from "../../protected-recovery/src/deny";
import { loadRecoveryAuthority } from "../../protected-recovery/src/model";
import { manifestPath } from "./workflow-authority";

// Print the required Deny matrix the broker runtime derives for one
// authority file and one platform commit set, in one form, as the JSON the
// Terraform module's required_deny_matrix output carries. The enabled-path
// Terraform harness renders this for every form and asserts equality with
// the module's own derivation, so the two definitions cannot drift apart.
//
//   bun run tools/ci/protected-recovery-matrix.ts <authority.json> <active-sha>[,<transition-sha>] [bootstrap|maintenance|steady] [deployment=<consumer>,...]

const [authorityPath, shas, form = "steady", deployment = ""] = Bun.argv.slice(2);
if (!authorityPath || !shas) throw new Error("Usage: protected-recovery-matrix.ts <authority.json> <active-sha>[,<transition-sha>] [steady|bootstrap|maintenance] [deployment=<consumer>,...]");
const root = join(import.meta.dir, "..", "..");
const authority = loadRecoveryAuthority(await readFile(authorityPath, "utf8"), await readFile(join(root, manifestPath), "utf8"));
const platformShas = shas.split(",").filter((sha) => sha.length > 0);
if (!platformShas.every((sha) => /^[0-9a-f]{40}$/.test(sha))) throw new Error("every platform commit must be one full lowercase SHA");
if (!["steady", "bootstrap", "maintenance"].includes(form)) throw new Error(`unknown form ${form}`);
const consumers = deployment.startsWith("deployment=") ? deployment.slice("deployment=".length).split(",").filter((consumer) => consumer.length > 0) : [];
const flags: DenyFlags = { bootstrap: form === "bootstrap", deployment: consumers, maintenance: form === "maintenance" };
console.log(JSON.stringify(denyMatrix(authority, { platformShas }, flags), null, 2));
