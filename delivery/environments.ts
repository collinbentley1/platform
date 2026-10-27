import { projects, type Project } from "./catalog.ts";
import { command, github, gcloud } from "./process.ts";

export async function environments(apps: readonly Project[] = projects): Promise<void> {
  if (Bun.env.GITHUB_ACTIONS) throw new Error("Environment enrollment requires the owner's session.");
  if (String((await github<{id:number}>("repos/collinbentley1/platform")).id) !== "1255856466") throw new Error("Platform repository identity changed.");
  for (const app of apps) {
    for (const purpose of ["publish","deploy","audit"]) {
      const name=`${purpose}-${app.name}`;const endpoint=`repos/collinbentley1/platform/environments/${name}`;
      await command(["gh","api","--method","PUT",endpoint,"--input","-"],{stdin:JSON.stringify({deployment_branch_policy:{protected_branches:false,custom_branch_policies:true}})});
      const policies=await github<{branch_policies:Array<{name:string;type:string}>}>(`${endpoint}/deployment-branch-policies`);
      if (!policies.branch_policies.some(rule=>rule.name==="main"&&rule.type==="branch")) await command(["gh","api","--method","POST",`${endpoint}/deployment-branch-policies`,"--input","-"],{stdin:JSON.stringify({name:"main",type:"branch"})});
    }
    if (app.identity) {
      const keys=await gcloud<Array<{name:string;displayName:string}>>(["services","api-keys","list",`--project=${app.project}`]);
      const key=keys.find(key=>key.displayName==="Public Identity Platform client");if(!key)throw new Error("Identity client configuration is missing.");
      const value=await gcloud<{keyString:string}>(["services","api-keys","get-key-string",key.name,`--project=${app.project}`]);
      await command(["gh","variable","set","IDENTITY_API_KEY","--repo","collinbentley1/platform","--env",`deploy-${app.name}`],{stdin:value.keyString,quiet:true});
    }
    if (app.name === "healthmcp") {
      const keys=await gcloud<Array<{name:string;displayName:string}>>(["recaptcha","keys","list",`--project=${app.project}`]);
      const selected=keys.filter(key=>key.displayName==="Medlock waitlist ownership");
      const siteKey=selected.length===1?selected[0]!.name.split("/").at(-1):undefined;
      if (!siteKey || !/^[A-Za-z0-9_-]{20,100}$/.test(siteKey)) throw new Error("Managed reCAPTCHA configuration is missing or ambiguous.");
      await command(["gh","variable","set","RECAPTCHA_SITE_KEY","--repo","collinbentley1/platform","--env",`deploy-${app.name}`],{stdin:siteKey,quiet:true});
    }
    if(app.name==="critical-history") {
      const token=Bun.env.MAPBOX_PUBLIC_TOKEN ?? await command(["gh","variable","get","MAPBOX_PUBLIC_TOKEN","--repo","collinbentley1/platform","--env",`deploy-${app.name}`],{quiet:true});
      if(!/^pk\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+$/.test(token.trim()))throw new Error("Critical History requires its protected public Mapbox configuration.");
      if(Bun.env.MAPBOX_PUBLIC_TOKEN)await command(["gh","variable","set","MAPBOX_PUBLIC_TOKEN","--repo","collinbentley1/platform","--env",`deploy-${app.name}`],{stdin:token.trim(),quiet:true});
    }
    console.log(JSON.stringify({event:"github-environments-enrolled",app:app.name,branches:["main"]}));
  }
}
if (import.meta.main) await environments();
