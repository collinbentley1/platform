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
