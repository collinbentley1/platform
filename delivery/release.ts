import { latestRelease } from "./upgrade.ts";
import { api, output } from "./github.ts";
if (Bun.argv[2] === "resolve") await output(await latestRelease());
else if (Bun.argv[2] === "publish") {
  const sha = Bun.env.GITHUB_SHA; const number = Bun.env.GITHUB_RUN_NUMBER;
  if (!sha || !/^[a-f0-9]{40}$/.test(sha) || !number || !/^[1-9][0-9]*$/.test(number) || Bun.env.GITHUB_REF !== "refs/heads/main" || Bun.env.GITHUB_REPOSITORY_ID !== "1255856466") throw new Error("Release authority differs.");
  if ((await api<{sha:string}>("/repos/collinbentley1/platform/commits/main")).sha !== sha) throw new Error("Release head is stale.");
  const tag = `v1.0.${number}`;
  const releases = await api<Array<{tag_name:string;target_commitish:string}>>("/repos/collinbentley1/platform/releases?per_page=100");
  const existing = releases.find(r=>r.tag_name===tag);
  if (existing && existing.target_commitish !== sha) throw new Error("Release tag already belongs to another source.");
  if (!existing) await api("/repos/collinbentley1/platform/releases","POST",{tag_name:tag,target_commitish:sha,name:tag,body:"Verified application platform release.",draft:false,prerelease:false,make_latest:"true"});
  await api("/repos/collinbentley1/platform/actions/workflows/upgrade-consumers.yml/dispatches","POST",{ref:"main"});
  console.log(JSON.stringify({event:"platform-release-published",tag,sha}));
} else throw new Error("Expected resolve or publish.");
