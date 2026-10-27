import {project} from '../delivery/catalog.ts';
if(Bun.env.GITHUB_ACTIONS || !Bun.argv.includes('--apply'))throw Error('Owner recovery drill: bun tools/recovery-drill.ts <registered-app> --apply (creates and removes a temporary Firestore clone).');
const app=project(Bun.argv[2]??'');if(!app.data)throw Error('Application has no managed datastore.');
import{command}from'../delivery/process.ts';import{google,GoogleError}from'../delivery/google.ts';
Bun.env.GOOGLE_OAUTH_ACCESS_TOKEN=await command(['gcloud','auth','print-access-token'],{quiet:true});
const base='https://firestore.googleapis.com/v1',source=`projects/${app.project}/databases/(default)`,id=`platform-recovery-${crypto.randomUUID().slice(0,8)}`,doc=`platform_recovery_proof/${crypto.randomUUID()}`,fixture={fields:{title:{stringValue:'Synthetic platform recovery proof'}}};
const config=await google<{pointInTimeRecoveryEnablement:string}>(`${base}/${source}`);if(config.pointInTimeRecoveryEnablement!=='POINT_IN_TIME_RECOVERY_ENABLED')throw Error('PITR is not enabled');
const created=await google<{updateTime:string}>(`${base}/${source}/documents/${doc}`,'PATCH',fixture);const snapshot=new Date(Math.ceil(Date.parse(created.updateTime)/60000)*60000).toISOString();
console.log(JSON.stringify({event:'recovery-fixture-created',snapshot,database:id,document:doc}));
let cloned=false;
try {
 while(Date.now()<Date.parse(snapshot)+5000)await Bun.sleep(Math.min(10000,Date.parse(snapshot)+5000-Date.now()));
 await google(`${base}/${source}/documents/${doc}`,'DELETE');
 try{await google(`${base}/${source}/documents/${doc}`);throw Error('Deleted fixture unexpectedly exists');}catch(error){if(!(error instanceof GoogleError&&error.status===404))throw error;}
 const clone=await google<{name:string}>(`${base}/projects/${app.project}/databases:clone`,'POST',{databaseId:id,pitrSnapshot:{database:source,snapshotTime:snapshot}});
 if(!clone.name.startsWith(`projects/${app.project}/databases/`))throw Error('Clone operation scope changed');cloned=true;
 const deadline=Date.now()+10*60000;
 for(;;){const state=await google<{done?:boolean;error?:unknown}>(`${base}/${clone.name}`);if(state.error)throw Error('PITR clone failed');if(state.done)break;if(Date.now()>deadline)throw Error('PITR clone timed out');await Bun.sleep(10000);}
 const restored=await google<typeof fixture>(`${base}/projects/${app.project}/databases/${id}/documents/${doc}`);
 if(JSON.stringify(restored.fields)!==JSON.stringify(fixture.fields))throw Error('Restored fixture content differs');
 console.log(JSON.stringify({result:'passed',proof:'Deleted synthetic document recovered from a real point-in-time clone',snapshot,database:id}));
} finally {
 await google(`${base}/${source}/documents/${doc}`,'DELETE');
 if(cloned){const name=`projects/${app.project}/databases/${id}`;const db=await google<{deleteProtectionState:string}>(`${base}/${name}`);if(db.deleteProtectionState==='DELETE_PROTECTION_ENABLED')await google(`${base}/${name}?updateMask=deleteProtectionState`,'PATCH',{name,deleteProtectionState:'DELETE_PROTECTION_DISABLED'});const removal=await google<{name:string}>(`${base}/${name}`,'DELETE');if(removal?.name){for(let i=0;i<30;i++){const state=await google<{done?:boolean;error?:unknown}>(`${base}/${removal.name}`);if(state.error)throw Error('Recovery fixture cleanup failed');if(state.done)break;await Bun.sleep(3000);}}console.log(JSON.stringify({event:'recovery-clone-removed',database:id}));}
}
