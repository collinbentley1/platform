import{test,expect}from"bun:test";
import{publicRevision,servingSource}from"../delivery/serving.ts";
test("public health must match a complete source/release pair from a routed revision",()=>{
  const a="a".repeat(40),b="b".repeat(40),c="c".repeat(40),d="d".repeat(40);
  const expected=[servingSource([{name:"PLATFORM_SOURCE_SHA",value:a},{name:"PLATFORM_RELEASE_SHA",value:b}]),{source:c,release:d}];
  const response=(source?:string,release?:string)=>Response.json({ok:true},{headers:{...(source?{"X-Platform-Source":source}:{}),...(release?{"X-Platform-Release":release}:{})}});
  expect(publicRevision(response(a,b),expected)).toBe(true);
  expect(publicRevision(response(c,d),expected)).toBe(true);
  expect(publicRevision(response(a,d),expected)).toBe(false);
  expect(publicRevision(response(),expected)).toBe(false);
  expect(()=>servingSource([])).toThrow("bound source");
});
