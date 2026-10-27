export type ServingSource = { source: string; release: string };
export function servingSource(environment: readonly {name:string;value?:string}[]): ServingSource {
  const source=environment.find(item=>item.name==="PLATFORM_SOURCE_SHA")?.value;
  const release=environment.find(item=>item.name==="PLATFORM_RELEASE_SHA")?.value;
  if(!source || !release || !/^[a-f0-9]{40}$/.test(source) || !/^[a-f0-9]{40}$/.test(release))throw new Error("Serving revision lacks bound source and release evidence.");
  return {source,release};
}
export function publicRevision(response: Response, expected: readonly ServingSource[]): boolean {
  return expected.some(item=>response.headers.get("X-Platform-Source")===item.source && response.headers.get("X-Platform-Release")===item.release);
}
