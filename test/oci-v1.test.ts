import {test,expect} from "bun:test";
import {mkdtemp,mkdir,writeFile,rm} from "node:fs/promises";
import {join} from "node:path";
import {tmpdir} from "node:os";
import {createHash} from "node:crypto";
import {verifyImage} from "../delivery/oci.ts";

test("OCI admission binds the entire image graph, source, architecture and non-root runtime", async()=>{
  const directory=await mkdtemp(join(tmpdir(),"oci-admission-"));
  const sha="a".repeat(40);
  try {
    await mkdir(join(directory,"blobs/sha256"),{recursive:true});
    const blob=async(value:unknown,mediaType:string)=>{
      const bytes=Buffer.from(typeof value==="string"?value:JSON.stringify(value));
      const digest="sha256:"+createHash("sha256").update(bytes).digest("hex");
      await writeFile(join(directory,"blobs/sha256",digest.slice(7)),bytes);
      return {digest,size:bytes.length,mediaType};
    };
    const config=await blob({os:"linux",architecture:"amd64",config:{User:"1000:1000",Labels:{"org.opencontainers.image.revision":sha,"io.collinbentley.platform.revision":sha}}},"application/vnd.oci.image.config.v1+json");
    const layer=await blob("opaque compressed bytes, never executed by admission","application/vnd.oci.image.layer.v1.tar+gzip");
    const manifest=await blob({schemaVersion:2,config,layers:[layer]},"application/vnd.oci.image.manifest.v1+json");
    await writeFile(join(directory,"oci-layout"),JSON.stringify({imageLayoutVersion:"1.0.0"}));
    await writeFile(join(directory,"index.json"),JSON.stringify({schemaVersion:2,manifests:[manifest]}));
    expect((await verifyImage(directory,sha,sha)).digest).toBe(manifest.digest);
    await expect(verifyImage(directory,"b".repeat(40),sha)).rejects.toThrow("source labels");
    await expect(verifyImage(directory,sha,sha,"arm64")).rejects.toThrow("architecture");
    const extra=await blob("unreferenced content","unused");
    await expect(verifyImage(directory,sha,sha)).rejects.toThrow("unreferenced");
    await rm(join(directory,"blobs/sha256",extra.digest.slice(7)));
    await writeFile(join(directory,"blobs/sha256",layer.digest.slice(7)),"different bytes");
    await expect(verifyImage(directory,sha,sha)).rejects.toThrow("digest differs");
  }finally{await rm(directory,{recursive:true,force:true});}
});
