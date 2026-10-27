import {test,expect} from "bun:test";
import {previewTraffic} from "../delivery/deploy.ts";
import {removeClosedTags} from "../delivery/cleanup.ts";
test("closed preview cleanup preserves the base route, open PR tags and operator tags",()=>{
  const traffic=[{revision:"bootstrap",percent:100},{revision:"closed",tag:"pr-3"},{revision:"open",tag:"pr-4"},{revision:"operator",tag:"investigation"}];
  const result=removeClosedTags(traffic,new Set(["pr-3"]));
  expect(result.map(item=>item.revision)).toEqual(["bootstrap","open","operator"]);
  expect(result[0]?.percent).toBe(100);
  expect(traffic).toHaveLength(4);
  expect(()=>removeClosedTags([{revision:"changed",percent:100,tag:"pr-3"}],new Set(["pr-3"]))).toThrow("base-service traffic");
});

test("preview promotion and rollback preserve other previews and the base route",()=>{
  const before=[{revision:"base",percent:100},{revision:"healthy",tag:"pr-3"},{revision:"other",tag:"pr-4"},{revision:"new",tag:"candidate-test"}];
  const promoted=previewTraffic(before,"pr-3","candidate-test","new");
  expect(JSON.parse(JSON.stringify(promoted.map(({revision,tag,percent})=>({revision,tag,percent}))))).toEqual([{revision:"base",percent:100},{revision:"other",tag:"pr-4"},{revision:"new",tag:"pr-3"}]);
  expect(previewTraffic(promoted,"pr-3","candidate-test","healthy").at(-1)).toMatchObject({revision:"healthy",tag:"pr-3"});
  expect(before[1]?.revision).toBe("healthy");
});
