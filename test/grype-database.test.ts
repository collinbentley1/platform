import { afterAll, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

const repo = resolve(import.meta.dir, "..");
const helper = join(repo, "tools/ci/container-artifact-contract.sh");
const roots: string[] = [];
const bytes = "verified database fixture";
const sha = (value: string | Buffer) => createHash("sha256").update(value).digest("hex");
const time = (hours = 1) => new Date(Date.now() - hours * 3_600_000).toISOString().replace(/\.\d{3}Z$/, "Z");
const path = "vulnerability-db_v6.1.9_2026-09-30T00:35:37Z_1790749967.tar.zst";
const manifest = (hours = 1, digest = sha(bytes)) => ({
  built: time(hours), schemaVersion: "v6.1.9", sha256: digest,
  url: `https://grype.anchore.io/databases/v6/${path}?checksum=sha256%3A${digest}`,
});
const listing = (hours = 1) => ({
  status: "active", schemaVersion: "v6.1.9", built: time(hours), path, checksum: `sha256:${sha(bytes)}`,
});

afterAll(async () => {
  for (const root of roots) {
    const chmod = Bun.spawn(["chmod", "-R", "u+w", root], { stdout: "ignore", stderr: "ignore" });
    await chmod.exited;
    await rm(root, { recursive: true, force: true });
  }
});

async function fixture() {
  const root = await mkdtemp(join(tmpdir(), "platform-grype-test-"));
  roots.push(root);
  await mkdir(join(root, "bin"));
  await writeFile(join(root, "listing.json"), JSON.stringify(listing()));
  await writeFile(join(root, "database"), bytes);
  await writeFile(join(root, "outputs"), "");
  await executable(join(root, "bin/curl"), `#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
out=Path(args[args.index('--output')+1])
root=Path(os.environ['FIXTURE_ROOT'])
kind='listing' if args[-1].endswith('latest.json') else 'database'
rc=int(os.environ.get('CURL_RC','0'))
status=os.environ.get('CURL_STATUS','200')
if kind=='database':
 rc=int(os.environ.get('ARCHIVE_RC',str(rc)))
 status=os.environ.get('ARCHIVE_STATUS',status)
if rc: sys.exit(rc)
out.write_bytes((root/('listing.json' if kind=='listing' else 'database')).read_bytes())
print(status,end='')
`);
  return root;
}

async function executable(path: string, source: string) {
  await writeFile(path, source);
  await chmod(path, 0o755);
}

async function run(root: string, command: string, overrides: Record<string, string> = {}, args: string[] = []) {
  const child = Bun.spawn(["/bin/bash", helper, command, ...args], {
    cwd: repo, stdout: "pipe", stderr: "pipe",
    env: {
      ...process.env, PATH: `${root}/bin:${process.env.PATH}`, FIXTURE_ROOT: root,
      RUNNER_OS: "Linux", RUNNER_ARCH: "X64", RUNNER_TEMP: root,
      GITHUB_RUN_ID: "300", GITHUB_RUN_ATTEMPT: "1", GITHUB_OUTPUT: join(root, "outputs"),
      GITHUB_REPOSITORY: "collinbentley1/cdbentley", GITHUB_REF: "refs/heads/main",
      REPOSITORY_ID: "1255553151", DB_MANIFEST_JSON: "", GRYPE_DB_MANIFEST_JSON: "",
      ...overrides,
    },
  });
  const [exitCode, stdout, stderr] = await Promise.all([
    child.exited, new Response(child.stdout).text(), new Response(child.stderr).text(),
  ]);
  return { exitCode, stdout, stderr, outputs: await readFile(join(root, "outputs"), "utf8") };
}

async function cache(root: string, data = manifest(), extras: Record<string, string> = {}) {
  const bundle = join(root, "cache-bundle");
  await mkdir(bundle);
  await mkdir(join(root, "platform-grype-cache-download"));
  await writeFile(join(bundle, "grype-db.tar.zst"), bytes);
  await writeFile(join(bundle, "manifest.json"), JSON.stringify(data));
  await writeFile(join(bundle, "policy.sha256"), `${sha(await readFile(join(repo, "tools/ci/grype-db-policy.json")))}\n`);
  for (const [name, value] of Object.entries(extras)) await writeFile(join(bundle, name), value);
  const archive = join(root, "platform-grype-cache-download/cache.tar");
  const tar = Bun.spawn(["tar", "--format=ustar", "-cf", archive, "-C", bundle, "."], { stdout: "ignore", stderr: "pipe" });
  expect(await tar.exited, await new Response(tar.stderr).text()).toBe(0);
  return sha(await readFile(archive));
}

describe("platform-owned Grype acquisition", () => {
  test("acquires current data and records its original timestamp and archive digest", async () => {
    const root = await fixture();
    const result = await run(root, "acquire-grype-db");
    expect(result.exitCode, result.stderr).toBe(0);
    const acquired = JSON.parse(await readFile(join(root, "platform-grype-database/manifest.json"), "utf8"));
    expect(acquired.built).toBe(JSON.parse(await readFile(join(root, "listing.json"), "utf8")).built);
    expect(acquired.sha256).toBe(sha(bytes));
    expect(result.outputs).toContain("source=upstream");
  });

  for (const overrides of [{ CURL_RC: "28" }, { CURL_STATUS: "503" }, { ARCHIVE_STATUS: "429" }]) {
    test(`uses only a verified fresh cache during ${JSON.stringify(overrides)}`, async () => {
      const root = await fixture();
      const previous = manifest(2);
      const digest = await cache(root, previous);
      const result = await run(root, "acquire-grype-db", { GRYPE_CACHE_CONTENT_SHA256: digest, ...overrides });
      expect(result.exitCode, result.stderr).toBe(0);
      expect(result.outputs).toContain("source=cache");
      expect(JSON.parse(await readFile(join(root, "platform-grype-database/manifest.json"), "utf8"))).toEqual(previous);
    });
  }

  test("reuses matching verified bytes after consulting the live feed", async () => {
    const root = await fixture();
    const digest = await cache(root);
    const result = await run(root, "acquire-grype-db", { GRYPE_CACHE_CONTENT_SHA256: digest, ARCHIVE_RC: "63" });
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.outputs).toContain("source=upstream");
  });

  test("fails an outage with no cache or with a cache over 48 hours old", async () => {
    for (const cached of [false, true]) {
      const root = await fixture();
      const digest = cached ? await cache(root, manifest(49)) : "";
      const result = await run(root, "acquire-grype-db", { GRYPE_CACHE_CONTENT_SHA256: digest, CURL_STATUS: "503" });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("no verified database under 48 hours old");
    }
  });

  for (const [label, patch] of Object.entries({
    stale: { built: time(49) }, future: { built: time(-2) }, schema: { schemaVersion: "v7" },
    traversal: { path: "../database.tar.zst" }, external: { path: "https://evil.example/database" },
    inactive: { status: "deprecated" }, malformedHash: { checksum: "sha256:short" }, extraKey: { injected: true },
    noncanonicalTime: { built: "2026-09-30T00:00:00+00:00" },
  })) {
    test(`rejects ${label} metadata even when a fresh cache exists`, async () => {
      const root = await fixture();
      await writeFile(join(root, "listing.json"), JSON.stringify({ ...listing(), ...patch }));
      const digest = await cache(root);
      const result = await run(root, "acquire-grype-db", { GRYPE_CACHE_CONTENT_SHA256: digest });
      expect(result.exitCode).not.toBe(0);
    });
  }

  test("rejects rollback and same-build archive substitution", async () => {
    for (const mutate of [false, true]) {
      const root = await fixture();
      const prior = manifest(mutate ? 1 : 0.5);
      if (mutate) {
        const upstream = listing();
        upstream.checksum = `sha256:${"a".repeat(64)}`;
        upstream.built = prior.built;
        await writeFile(join(root, "listing.json"), JSON.stringify(upstream));
      }
      const result = await run(root, "acquire-grype-db", { GRYPE_CACHE_CONTENT_SHA256: await cache(root, prior) });
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("rollback or same-build substitution");
    }
  });

  test("fails on corrupt bytes, oversized download errors, authorization errors, and unexpected cache entries", async () => {
    for (const variant of ["hash", "cap", "403", "cache-hash", "cache-entry"]) {
      const root = await fixture();
      const overrides: Record<string, string> = {};
      if (variant === "hash") await writeFile(join(root, "database"), "corrupt");
      if (variant === "cap") overrides.CURL_RC = "63";
      if (variant === "403") overrides.CURL_STATUS = "403";
      if (variant.startsWith("cache")) {
        const digest = await cache(root, manifest(), variant === "cache-entry" ? { "extra": "bad" } : {});
        overrides.GRYPE_CACHE_CONTENT_SHA256 = variant === "cache-hash" ? "a".repeat(64) : digest;
      }
      const result = await run(root, "acquire-grype-db", overrides);
      expect(result.exitCode, variant).not.toBe(0);
    }
  });

  test("enforces freshness at the final mutation boundary", async () => {
    const root = await fixture();
    expect((await run(root, "check-grype-freshness", {}, [time(1)])).exitCode).toBe(0);
    for (const built of [time(49), time(-2), "invalid"]) {
      expect((await run(root, "check-grype-freshness", {}, [built])).exitCode).not.toBe(0);
    }
  });
});

async function github(root: string, responses: Record<string, unknown>) {
  await writeFile(join(root, "github.json"), JSON.stringify(responses));
  await executable(join(root, "bin/gh"), `#!/usr/bin/python3
import json,os,sys
from pathlib import Path
responses=json.loads((Path(os.environ['FIXTURE_ROOT'])/'github.json').read_text())
endpoint=sys.argv[-1]
for key,value in responses.items():
 if key in endpoint:
  print(json.dumps(value))
  sys.exit(0)
sys.exit(1)
`);
}

const productionRun = (id: number, conclusion = "success") => ({
  id, conclusion, head_branch: "main", event: "push", run_attempt: 1,
  path: ".github/workflows/deploy-prod.yml", repository: { id: 1255553151 },
  head_repository: { id: 1255553151 }, head_sha: "a".repeat(40),
});
const artifact = (original: number, producer = original) => ({
  id: producer + 1000, name: producer === original ? `platform-production-sbom-${original}-1.tar` : `platform-production-sbom-${original}-rescan-${producer}.tar`,
  expired: false, size_in_bytes: 1000, digest: `sha256:${"b".repeat(64)}`,
  workflow_run: { id: producer, repository_id: 1255553151, head_repository_id: 1255553151 },
});

describe("production SBOM inventory", () => {
  test("covers the last successful release plus newer published candidates, excluding unrelated runs", async () => {
    const root = await fixture();
    await github(root, {
      "workflows/deploy-prod.yml/runs": { workflow_runs: [productionRun(102, "failure"), { ...productionRun(103), event: "pull_request" }, productionRun(101), productionRun(100)] },
      "runs/102/artifacts": { artifacts: [artifact(102)] }, "runs/101/artifacts": { artifacts: [artifact(101)] },
    });
    const result = await run(root, "discover-production-sbom");
    expect(result.exitCode, result.stderr).toBe(0);
    expect(JSON.parse(result.outputs.trim().slice("matrix=".length)).include.map((item: { deploymentRunId: string }) => item.deploymentRunId)).toEqual(["102", "101"]);
  });

  test("fails instead of reporting a zero-target success before adoption", async () => {
    const root = await fixture();
    await github(root, { "workflows/deploy-prod.yml/runs": { workflow_runs: [productionRun(101)] }, "runs/101/artifacts": { artifacts: [] } });
    const result = await run(root, "discover-production-sbom");
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("no retained production SBOM");
  });

  for (const event of ["schedule", "pull_request"]) {
    test(`renewal from ${event} ${event === "schedule" ? "remains eligible after a vulnerability gate failure" : "is rejected"}`, async () => {
      const root = await fixture();
      await github(root, {
        "workflows/deploy-prod.yml/runs": { workflow_runs: [productionRun(101)] },
        "runs/101/artifacts": { artifacts: [] },
        "workflows/rescan-vulnerabilities.yml/runs": { workflow_runs: [{ ...productionRun(200, "failure"), event, path: ".github/workflows/rescan-vulnerabilities.yml" }] },
        "runs/200/artifacts": { artifacts: [artifact(101, 200)] },
      });
      const result = await run(root, "discover-production-sbom");
      expect(result.exitCode, result.stderr).toBe(event === "schedule" ? 0 : 1);
      if (event === "schedule") expect(result.outputs).toContain('"artifactRunId":"200"');
    });
  }

  test("refuses to silently truncate an excessive partial-deployment inventory", async () => {
    const root = await fixture();
    const runs = Array.from({ length: 9 }, (_, i) => productionRun(109 - i, i === 8 ? "success" : "failure"));
    const responses: Record<string, unknown> = { "workflows/deploy-prod.yml/runs": { workflow_runs: runs } };
    for (const item of runs) responses[`runs/${item.id}/artifacts`] = { artifacts: [artifact(item.id)] };
    await github(root, responses);
    const result = await run(root, "discover-production-sbom");
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("More than eight");
  });
});

describe("cache producer identity", () => {
  const producer = {
    ...productionRun(400), event: "schedule", path: ".github/workflows/refresh-grype-db.yml",
    created_at: time(), repository: { id: 1255856466 }, head_repository: { id: 1255856466 },
  };
  const saved = {
    ...artifact(400), name: "platform-grype-db-400-1.tar",
    workflow_run: { id: 400, repository_id: 1255856466, head_repository_id: 1255856466 },
  };
  for (const variant of ["valid", "PR", "rerun", "fork", "path", "expired", "digest", "duplicate"]) {
    test(`cache discovery ${variant === "valid" ? "accepts the bound producer" : `rejects ${variant}`}`, async () => {
      const root = await fixture();
      const runPatch = variant === "PR" ? { event: "pull_request" } : variant === "rerun" ? { run_attempt: 2 }
        : variant === "fork" ? { head_repository: { id: 999 } } : variant === "path" ? { path: ".github/workflows/other.yml" } : {};
      const artifactPatch = variant === "expired" ? { expired: true } : variant === "digest" ? { digest: null } : {};
      const item = { ...saved, ...artifactPatch };
      await github(root, {
        "workflows/refresh-grype-db.yml/runs": { workflow_runs: [{ ...producer, ...runPatch }] },
        "runs/400/artifacts": { artifacts: variant === "duplicate" ? [item, item] : [item] },
      });
      const result = await run(root, "discover-grype-cache");
      expect(result.exitCode, result.stderr).toBe(0);
      expect(result.outputs.includes("artifact_id=")).toBe(variant === "valid");
    });
  }
});

describe("database policy migration and parsing", () => {
  test("ignores a bound cache from another policy and requires verified upstream data", async () => {
    for (const unavailable of [false, true]) {
      const root = await fixture();
      const digest = await cache(root, manifest(), { "policy.sha256": `${"a".repeat(64)}\n` });
      const result = await run(root, "acquire-grype-db", {
        GRYPE_CACHE_CONTENT_SHA256: digest, CURL_STATUS: unavailable ? "503" : "200",
      });
      expect(result.exitCode, result.stderr).toBe(unavailable ? 1 : 0);
      if (!unavailable) expect(result.outputs).toContain("source=upstream");
    }
  });

  test("rejects multiple JSON documents rather than validating only the final document", async () => {
    const root = await fixture();
    await writeFile(join(root, "listing.json"), `{}\n${JSON.stringify(listing())}\n`);
    const result = await run(root, "acquire-grype-db");
    expect(result.exitCode).not.toBe(0);
    expect(result.stderr).toContain("exactly one JSON document");
  });
});

async function productionBundle(root: string, overrides: Record<string, unknown> = {}) {
  const source = join(root, "platform-build");
  await mkdir(source);
  const sbom = JSON.stringify({ spdxVersion: "SPDX-2.3", packages: [] });
  const evidence = JSON.stringify({
    schemaVersion: 1, imageDigest: `sha256:${"d".repeat(64)}`, sbomSha256: sha(sbom),
    resultSha256: "e".repeat(64), policySha256: sha(await readFile(join(repo, "tools/ci/grype-db-policy.json"))),
    database: manifest(), grypeVersion: "0.117.0", blockingCount: 0, scannedAt: time(),
  });
  await writeFile(join(source, "sbom.spdx.json"), sbom);
  await writeFile(join(source, "scan-evidence.json"), evidence);
  await writeFile(join(source, "manifest.json"), JSON.stringify({
    schemaVersion: 2, repositoryId: "1255553151", runId: "300", runAttempt: "1", eventName: "push", headSha: "a".repeat(40),
    publishedIndexDigest: `sha256:${"d".repeat(64)}`, sbomSha256: sha(sbom), scanEvidenceSha256: sha(evidence), workflowSha: "c".repeat(40),
    ...overrides,
  }));
  return {
    GITHUB_WORKSPACE: root, GITHUB_SHA: "a".repeat(40),
    PUBLISHED_IMAGE_NAME: "us-east4-docker.pkg.dev/cdbentley/site/cdbentley", PUBLISHED_IMAGE_DIGEST: `sha256:${"d".repeat(64)}`,
  };
}

describe("production evidence retention", () => {
  test("retains only the bound published image, SBOM, and original scan evidence", async () => {
    const root = await fixture();
    const env = await productionBundle(root);
    const result = await run(root, "retain-production-sbom", env);
    expect(result.exitCode, result.stderr).toBe(0);
    const record = JSON.parse(await readFile(join(root, "platform-production-sbom-bundle/record.json"), "utf8"));
    expect(record.deploymentRunId).toBe("300");
    expect(record.imageDigest).toBe(env.PUBLISHED_IMAGE_DIGEST);
    expect(record.workflowSha).toBe("c".repeat(40));
    expect(await readFile(join(root, "platform-production-sbom-bundle/scan-evidence.json"), "utf8")).toBe(await readFile(join(root, "platform-build/scan-evidence.json"), "utf8"));
  });

  for (const variant of ["head", "repo", "image", "sbom", "evidence", "stale"]) {
    test(`rejects ${variant} substitution or expiry before retention`, async () => {
      const root = await fixture();
      const env = await productionBundle(root, variant === "head" ? { headSha: "b".repeat(40) } : variant === "repo" ? { repositoryId: "999" } : {});
      if (variant === "image") env.PUBLISHED_IMAGE_DIGEST = `sha256:${"e".repeat(64)}`;
      if (variant === "sbom") await writeFile(join(root, "platform-build/sbom.spdx.json"), "{}");
      if (variant === "evidence" || variant === "stale") {
        const path = join(root, "platform-build/scan-evidence.json");
        const evidence = JSON.parse(await readFile(path, "utf8"));
        evidence.resultSha256 = variant === "evidence" ? "f".repeat(64) : evidence.resultSha256;
        evidence.scannedAt = variant === "stale" ? time(49) : time();
        evidence.database.built = variant === "stale" ? time(49) : time();
        const data = JSON.stringify(evidence);
        await writeFile(path, data);
        if (variant === "stale") {
          const manifestPath = join(root, "platform-build/manifest.json");
          const value = JSON.parse(await readFile(manifestPath, "utf8"));
          value.scanEvidenceSha256 = sha(data);
          await writeFile(manifestPath, JSON.stringify(value));
        }
      }
      const result = await run(root, "retain-production-sbom", env);
      expect(result.exitCode, variant).not.toBe(0);
      expect(result.outputs).not.toContain("artifact=");
    });
  }
});

// These fixtures replace only scanner transport/execution, leaving archive,
// policy, image/run binding, freshness, evidence and renewal checks executable.
describe("networkless rescan orchestration", () => {
  for (const variant of ["clean", "high", "scanner-failure", "wrong-head", "tampered-sbom"]) {
    test(`${variant} preserves the correct scan and renewal outcome`, async () => {
      const root = await fixture();
      const env = await productionBundle(root);
      const retained = await run(root, "retain-production-sbom", env);
      expect(retained.exitCode, retained.stderr).toBe(0);
      await writeFile(join(root, "outputs"), "");
      const bundle = join(root, "platform-production-sbom-bundle");
      const original = JSON.parse(await readFile(join(bundle, "scan-evidence.json"), "utf8"));
      original.scannedAt = time(720);
      original.database.built = time(720);
      const evidence = JSON.stringify(original);
      await writeFile(join(bundle, "scan-evidence.json"), evidence);
      const record = JSON.parse(await readFile(join(bundle, "record.json"), "utf8"));
      record.scanEvidenceSha256 = sha(evidence);
      await writeFile(join(bundle, "record.json"), JSON.stringify(record));
      if (variant === "tampered-sbom") await writeFile(join(bundle, "sbom.spdx.json"), "{}");
      await mkdir(join(root, "platform-sbom-download"));
      const artifactPath = join(root, "platform-sbom-download/sbom.tar");
      const tar = Bun.spawn(["tar", "--format=ustar", "-cf", artifactPath, "-C", bundle, "."], { stderr: "pipe", stdout: "ignore" });
      expect(await tar.exited).toBe(0);
      const dbResult = await run(root, "acquire-grype-db");
      expect(dbResult.exitCode, dbResult.stderr).toBe(0);
      const databaseDir = join(root, "platform-grype-database");
      const dbManifest = JSON.parse(await readFile(join(databaseDir, "manifest.json"), "utf8"));
      const policy = join(root, "test-policy");
      await mkdir(policy);
      for (const file of ["container-artifact-contract.sh", "grype-database.sh", "grype-db-policy.json", "grype-blocking.jq", "grype.yaml"]) {
        await writeFile(join(policy, file), await readFile(join(repo, "tools/ci", file)));
      }
      await chmod(policy, 0o700);
      await chmod(join(policy, "grype.yaml"), 0o600);
      const tools = join(root, "fixture-tools");
      await mkdir(tools);
      await executable(join(tools, "grype"), `#!/bin/bash\necho '{"version":"0.117.0","gitCommit":"b5fa92bbcbef655497e3be840a2f718380e2cdd3"}'\n`);
      const scannerTar = join(root, "fixture-scanner.tgz");
      const archive = Bun.spawn(["tar", "-czf", scannerTar, "-C", tools, "grype"], { stderr: "pipe", stdout: "ignore" });
      expect(await archive.exited).toBe(0);
      const rescan = (await readFile(join(repo, "tools/ci/grype-rescan.sh"), "utf8")).replace("38525dab1e06f162ebaa02f94d82d1f807076b011a44180cf2777edf1a7b9c26", sha(await readFile(scannerTar)));
      await writeFile(join(policy, "grype-rescan.sh"), rescan);
      await executable(join(root, "bin/curl"), `#!/usr/bin/python3
import os,sys
from pathlib import Path
args=sys.argv[1:]
assert args[-1]=='https://github.com/anchore/grype/releases/download/v0.117.0/grype_0.117.0_linux_amd64.tar.gz'
Path(args[args.index('--output')+1]).write_bytes((Path(os.environ['FIXTURE_ROOT'])/'fixture-scanner.tgz').read_bytes())
`);
      const sandboxImage = "moby/buildkit@sha256:28a898719c18a33f4e8000685287fa36fd0dd9560c6440227d3a732d79bb41d8";
      await executable(join(root, "bin/docker"), `#!/usr/bin/python3
import json,os,sys
from pathlib import Path
args=sys.argv[1:]
root=Path(os.environ['FIXTURE_ROOT'])
if args[0]=='pull':
 assert args[1]==${JSON.stringify(sandboxImage)}
 sys.exit(0)
if args[:2]==['image','inspect']:
 print(json.dumps([${JSON.stringify(sandboxImage)}]) if '.RepoDigests' in args[3] else 'sha256:'+('f'*64))
 sys.exit(0)
assert args[0]=='run'
for pair in [['--network','none'],['--user','65534:65534'],['--cap-drop','ALL'],['--security-opt','no-new-privileges'],['--pids-limit','256'],['--pull','never']]:
 assert any(args[i:i+2]==pair for i in range(len(args)-1)),pair
assert '--read-only' in args and '--privileged' not in args
assert args[args.index('--memory')+1]==('4294967296' if 'import' in args else '1073741824')
for value in args:
 assert 'docker.sock' not in value and 'GH_TOKEN' not in value and 'AR_ACCESS_TOKEN' not in value
mounts=[args[i+1] for i,v in enumerate(args) if v=='--mount']
for target in ['/input','/tools','/policy','/database']:
 assert any('dst='+target+',readonly' in m for m in mounts)
policy=root/'platform-rescan-policy'
assert policy.stat().st_mode & 0o005 == 0o005
assert (policy/'grype.yaml').stat().st_mode & 0o004 == 0o004
assert [p.name for p in policy.iterdir()]==['grype.yaml']
assert (policy/'grype.yaml').read_bytes()==(root/'test-policy/grype.yaml').read_bytes()
if 'import' in args: sys.exit(0)
if 'status' in args:
 expected=json.loads((root/'platform-grype-database/manifest.json').read_text())
 print(json.dumps({'valid':True,'built':expected['built'],'schemaVersion':expected['schemaVersion']}))
 sys.exit(0)
assert 'sbom:/input/sbom.spdx.json' in args
if os.environ['SCAN_VARIANT']=='scanner-failure': sys.exit(1)
matches=[] if os.environ['SCAN_VARIANT']!='high' else [{'artifact':{'name':'fixture','version':'1'},'vulnerability':{'id':'GHSA-fixture','severity':'High','fix':{'state':'not-fixed','versions':[]}}}]
print(json.dumps({'matches':matches}))
`);
      const child = Bun.spawn(["/bin/bash", join(policy, "container-artifact-contract.sh"), "rescan-sbom"], {
        stdout: "pipe", stderr: "pipe", env: {
          ...process.env, ...env, PATH: `${root}/bin:${process.env.PATH}`, FIXTURE_ROOT: root,
          SCAN_VARIANT: variant, RUNNER_OS: "Linux", RUNNER_ARCH: "X64", RUNNER_TEMP: root,
          GITHUB_RUN_ID: "400", GITHUB_RUN_ATTEMPT: "1", GITHUB_OUTPUT: join(root, "scan-outputs"),
          REPOSITORY_ID: "1255553151", RESCAN_ARTIFACT_SHA256: sha(await readFile(artifactPath)),
          RESCAN_DEPLOYMENT_RUN_ID: "300", RESCAN_HEAD_SHA: (variant === "wrong-head" ? "b" : "a").repeat(40),
          GRYPE_DATABASE_DIR: databaseDir, GRYPE_DATABASE_MANIFEST_SHA256: sha(await readFile(join(databaseDir, "manifest.json"))),
        },
      });
      const [code, stderr] = await Promise.all([child.exited, new Response(child.stderr).text(), new Response(child.stdout).text()]);
      const completes = variant === "clean" || variant === "high";
      expect(code, stderr).toBe(completes ? 0 : 1);
      if (completes) {
        const output = await readFile(join(root, "scan-outputs"), "utf8");
        expect(output).toContain(`blocking_count=${variant === "high" ? 1 : 0}`);
        expect(output).toContain("inventory_artifact=");
        const report = JSON.parse(await readFile(join(root, "platform-rescan-report/rescan-evidence.json"), "utf8"));
        expect(report.database).toEqual(dbManifest);
        expect(report.imageDigest).toBe(env.PUBLISHED_IMAGE_DIGEST);
        expect(await readFile(join(root, "platform-rescan-source/scan-evidence.json"), "utf8")).toBe(evidence);
      }
    });
  }
});
