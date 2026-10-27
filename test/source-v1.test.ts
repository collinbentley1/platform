import {test,expect} from "bun:test";
import {resolveSource} from "../delivery/resolve-source.ts";
import type {PullRequest} from "../delivery/github.ts";
test("manual verification uses the requested PR head instead of silently verifying main",async()=>{
  const main="a".repeat(40),head="b".repeat(40);
  const read=async(number:string)=>{expect(number).toBe("42");return {head:{sha:head},draft:false} as PullRequest;};
  expect(await resolveSource("42",main,read)).toEqual({sha:head,pr:"42",reviewable:"true"});
  expect(await resolveSource("",main,read)).toEqual({sha:main,pr:"",reviewable:"false"});
  await expect(resolveSource("42;echo injected",main,read)).rejects.toThrow("Invalid requested");
});

 test("production probes use the application's configured public host",async()=>{
 const {productionOrigin}=await import("../delivery/deploy.ts"); const {project}=await import("../delivery/catalog.ts");
 expect(productionOrigin(project("virtual-care-mcp"),"https://internal-alias.run.app")).toBe("https://virtual-care-mcp-894875537243.us-east4.run.app");
 expect(productionOrigin(project("healthmcp"),"https://internal-alias.run.app")).toBe("https://medlock.ai");
 expect(productionOrigin(project("runsetta"),"https://internal-alias.run.app")).toBe("https://runsetta.com");
 expect(productionOrigin(project("critical-history"),"https://internal-alias.run.app")).toBe("https://ycriticalhistory.org");
 expect(productionOrigin(project("cdbentley"),"https://internal-alias.run.app")).toBe("https://cdbentley.com");
 });

test("delivery source checks are independent of deployment outcomes and still require every validation app",async()=>{const{sourceChecksPassed}=await import("../delivery/prepare.ts"),{project}=await import("../delivery/catalog.ts");let id=0;const check=(name:string,app:number,conclusion="success")=>({id:++id,name,app:{id:app},status:"completed",conclusion});const base=[check("Platform verify",15368),check("Terraform modules",15368),check("Complete starter and container",15368),check("Socket Security: Project Report",156372),check("Socket Security: Pull Request Alerts",156372)];expect(sourceChecksPassed(project("platform-reference"),[...base,check("deploy (unrelated application)",15368,"failure")])).toBe(true);expect(sourceChecksPassed(project("platform-reference"),[...base,check("Terraform modules",15368,"failure")])).toBe(false);expect(sourceChecksPassed(project("platform-reference"),base.filter(c=>c.app.id!==156372))).toBe(false);const consumer=[check("Bun verify / Bun verify",15368),...base.filter(c=>c.app.id===156372)];expect(sourceChecksPassed(project("runsetta"),consumer)).toBe(false);expect(sourceChecksPassed(project("runsetta"),[...consumer,check("Swift package check",15368)])).toBe(true);});

test("production admits squash commits without PR-only Socket checks while previews require them",async()=>{const{sourceChecksPassed}=await import("../delivery/prepare.ts"),{project}=await import("../delivery/catalog.ts");const main=[{id:1,name:"Bun verify / Bun verify",app:{id:15368},status:"completed",conclusion:"success"},{id:2,name:"Socket Security: Project Report",app:{id:156372},status:"completed",conclusion:"success"}];expect(sourceChecksPassed(project("cdbentley"),main)).toBe(true);expect(sourceChecksPassed(project("cdbentley"),main,true)).toBe(false);expect(sourceChecksPassed(project("cdbentley"),[...main,{id:3,name:"Socket Security: Pull Request Alerts",app:{id:156372},status:"completed",conclusion:"success"}],true)).toBe(true);});
