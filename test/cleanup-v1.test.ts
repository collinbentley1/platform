import {test,expect} from "bun:test";
import {removeClosedTags} from "../delivery/cleanup.ts";
test("closed preview cleanup preserves the base route, open PR tags and operator tags",()=>{
  const traffic=[{revision:"bootstrap",percent:100},{revision:"closed",tag:"pr-3"},{revision:"open",tag:"pr-4"},{revision:"operator",tag:"investigation"}];
  const result=removeClosedTags(traffic,new Set(["pr-3"]));
  expect(result.map(item=>item.revision)).toEqual(["bootstrap","open","operator"]);
  expect(result[0]?.percent).toBe(100);
  expect(traffic).toHaveLength(4);
  expect(()=>removeClosedTags([{revision:"changed",percent:100,tag:"pr-3"}],new Set(["pr-3"]))).toThrow("base-service traffic");
});
