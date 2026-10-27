import { describe, test, expect } from "bun:test";
import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { doctor, upgrade, runtimeManifest, runtimeFiles } from "../delivery/consumer.ts";
import {validateCatalog} from "../delivery/catalog.ts";
import catalog from "../delivery/projects.json";

test("catalog proposals cannot raise cost ceilings or provide invalid capacity",()=>{
  validateCatalog(structuredClone(catalog));
  for(const defaults of [{...catalog.defaults,monthlyBudgetUSD:31},{...catalog.defaults,monthlyBudgetUSD:NaN},{...catalog.defaults,productionMaxInstances:3},{...catalog.defaults,productionMaxInstances:0},{...catalog.defaults,productionMaxInstances:1.5},{...catalog.defaults,previewMaxInstances:2}])expect(()=>validateCatalog({...structuredClone(catalog),defaults})).toThrow("budget or capacity");
});

const source = resolve(import.meta.dir, "..");
const first = "a".repeat(40); const second = "b".repeat(40);
describe("managed platform upgrades", () => {
  test("upgrades the complete contract without changing product files, and repeated runs make no changes", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-upgrade-"));
    try {
      await writeFile(join(root, "product.ts"), "custom frontend and product code");
      await mkdir(join(root, "src"));
      await writeFile(join(root, "src/server.ts"), 'import {secureHandler} from "../.platform/runtime/http.ts";\nexport const handler = secureHandler(() => new Response("custom"));\n');
      await upgrade(root, source, first, { adopt: true }); expect(await doctor(root, source, first)).toEqual([]);
      const planned = await upgrade(root, source, second, { check: true }); expect(planned).toContain(".platform/release.json");
      expect(JSON.parse(await readFile(join(root, ".platform/release.json"), "utf8")).sha).toBe(first);
      await upgrade(root, source, second); expect(await doctor(root, source, second)).toEqual([]);
      expect(await upgrade(root, source, second)).toEqual([]);
      expect(await readFile(join(root, "product.ts"), "utf8")).toBe("custom frontend and product code");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
  test("refuses to overwrite managed edits before writing any file", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-upgrade-"));
    try {
      await upgrade(root, source, first, { adopt: true }); const lock = await readFile(join(root, ".platform/release.json"), "utf8");
      await writeFile(join(root, ".platform/runtime/http.ts"), "a local change");
      await expect(upgrade(root, source, second)).rejects.toThrow("local managed-file change");
      expect(await readFile(join(root, ".platform/release.json"), "utf8")).toBe(lock);
      expect(await readFile(join(root, ".platform/runtime/http.ts"), "utf8")).toBe("a local change");
    } finally { await rm(root, { recursive: true, force: true }); }
  });
});

test("runtime dependency upgrades preserve product dependencies and scripts",()=>{ const current=JSON.stringify({dependencies:{product:"9.0.0"},scripts:{start:"custom"},packageManager:"bun@1.4.0"}); const next=runtimeManifest(current,JSON.stringify({dependencies:{jose:"6.1.3"}}),"bun@1.4.2"); expect(JSON.parse(next)).toEqual({dependencies:{product:"9.0.0",jose:"6.1.3"},scripts:{start:"custom"},packageManager:"bun@1.4.2"});expect(runtimeManifest(next,JSON.stringify({dependencies:{jose:"6.1.3"}}),"bun@1.4.2")).toBe(next);});

test("runtime generation has a canonical order across filesystem enumeration orders",async()=>{const root=await mkdtemp(join(tmpdir(),"platform-order-"));try{for(const name of ["first","second"]){await mkdir(join(root,name,"runtime"),{recursive:true});const names=name==="first"?["http.ts","auth.ts","data.ts","package.json"]:["package.json","data.ts","auth.ts","http.ts"];for(const file of names)await writeFile(join(root,name,"runtime",file),file);}const first=await runtimeFiles(join(root,"first")),second=await runtimeFiles(join(root,"second"));expect(Object.keys(first)).toEqual([".platform/runtime/auth.ts",".platform/runtime/data.ts",".platform/runtime/http.ts",".platform/runtime/package.json"]);expect(JSON.stringify(first)).toBe(JSON.stringify(second));}finally{await rm(root,{recursive:true,force:true});}});
