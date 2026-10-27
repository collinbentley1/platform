import {test,expect} from "bun:test";
import {previewTraffic,productionTraffic,normalizedTraffic,routingState} from "../delivery/deploy.ts";
import {removeClosedTags} from "../delivery/cleanup.ts";
test("closed preview cleanup preserves the base route, open PR tags and operator tags",()=>{
  const traffic=[{revision:"bootstrap",percent:100},{revision:"closed",tag:"pr-3"},{revision:"open",tag:"pr-4"},{revision:"operator",tag:"investigation"}];
  const result=removeClosedTags(traffic,new Set(["pr-3"]));
  expect(result.map(item=>item.revision)).toEqual(["bootstrap","open","operator"]);
  expect(result[0]?.percent).toBe(100);
  expect(traffic).toHaveLength(4);
  expect(()=>removeClosedTags([{revision:"changed",percent:100,tag:"pr-3"}],new Set(["pr-3"]))).toThrow("base-service traffic");
});

test("production promotion preserves tagged routes and rollback restores their complete prior state",()=>{
  const previous=[{revision:"base",percent:100},{revision:"debug",tag:"investigation"},{revision:"base",tag:"support",percent:0}];
  const promoted=productionTraffic([...previous,{revision:"new",tag:"candidate-test"}],"new","candidate-test");
  expect(promoted.find(item=>item.tag==="investigation")).toMatchObject({revision:"debug"});
  expect(promoted.find(item=>item.tag==="support")).toMatchObject({revision:"base"});
  expect(promoted.some(item=>item.tag==="candidate-test")).toBe(false);
  expect(routingState(normalizedTraffic(previous))).toBe(routingState(previous));
  expect(routingState([...promoted,{revision:"operator",tag:"new-debug"}])).not.toBe(routingState(promoted));
});

test("preview promotion and rollback preserve other previews and the base route",()=>{
  const before=[{revision:"base",percent:100},{revision:"healthy",tag:"pr-3"},{revision:"other",tag:"pr-4"},{revision:"new",tag:"candidate-test"}];
  const promoted=previewTraffic(before,"pr-3","candidate-test","new");
  expect(JSON.parse(JSON.stringify(promoted.map(({revision,tag,percent})=>({revision,tag,percent}))))).toEqual([{revision:"base",percent:100},{revision:"other",tag:"pr-4"},{revision:"new",tag:"pr-3"}]);
  expect(previewTraffic(promoted,"pr-3","candidate-test","healthy").at(-1)).toMatchObject({revision:"healthy",tag:"pr-3"});
  expect(before[1]?.revision).toBe("healthy");
  const coalesced=previewTraffic([{revision:"base",percent:100,tag:"pr-3"}],"pr-3","candidate-test","new");
  expect(coalesced[0]).toMatchObject({revision:"base",percent:100});expect(coalesced[0]?.tag).toBeUndefined();
  expect(coalesced.at(-1)).toMatchObject({revision:"new",tag:"pr-3"});
});
