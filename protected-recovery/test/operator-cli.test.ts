import { expect, test } from "bun:test";
import { chmod, copyFile, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { coordinates, Journal } from "../operator.ts";
import { canonicalJson } from "../src/model.ts";

const root = join(import.meta.dir, "../..");
const sha = "a".repeat(40);
const pushSha = "b".repeat(40);
const prSha = "c".repeat(40);
const syncSha = "d".repeat(40);
const target = coordinates(["owner/consumer", "CONTROL", "-", "cli-test"]);
const platform = "collinbentley1/platform";
const branch = `protected-recovery/delivery-${target.round}`;
const member = `principalSet://iam.googleapis.com/pool/attribute.authority/owner/consumer/.github/workflows/deploy-prod.yml@refs/heads/main:${platform}/.github/workflows/deploy-prod.yml@${sha}:${sha}:prod:push`;
const binding = { [member]: { runId: "20", runAttempt: "1" } };

// Both command names resolve only to this fixture. An unmodeled command fails
// closed, including any attempt to create a PR or replay a consumer dispatch.
const fakeCli = `#!${process.execPath}
import { readFileSync, writeFileSync, mkdirSync } from 'node:fs';
import { basename, join } from 'node:path';
const path = process.env.OPERATOR_FIXTURE_STATE;
const state = JSON.parse(readFileSync(path, 'utf8'));
const args = process.argv.slice(2);
const binary = basename(process.argv[1]);
state.calls.push([binary, ...args]);
const save = () => writeFileSync(path, JSON.stringify(state));
const output = value => { save(); console.log(typeof value === 'string' ? value : JSON.stringify(value)); process.exit(0); };
const fail = message => { save(); console.error(message); process.exit(1); };
if (binary === 'git') {
  if (args[0] === 'show') output(state.templates[args[1].split('/').at(-1)]);
  if (args[0] === 'ls-remote' && args[2] === state.remote && args[3] === state.ref) output(state.branchHead ? state.branchHead + '\\t' + state.ref : '');
  if (args[0] === 'push' && args[2] === '--force-with-lease=' + state.ref + ':' + state.branchHead && args[3] === state.remote && args[4] === ':' + state.ref) {
    state.branchHead = null; state.deletes += 1; output('');
  }
  fail('unexpected fake git command: ' + JSON.stringify(args));
}
if (args[0] === 'auth' && args[1] === 'status') output('authenticated fixture');
if (args[0] === 'pr' && args[1] === 'close' && args[2] === '7') {
  state.pr.state = 'closed'; state.closes += 1;
  if (state.loseCloseResponse) { state.loseCloseResponse = false; fail('simulated lost close response'); }
  output('');
}
if (args[0] === 'run' && args[1] === 'watch') output('');
if (args[0] === 'run' && args[1] === 'download') {
  const entry = state.invocations.find(entry => String(entry.run.id) === args[2]);
  if (!entry) fail('unknown downloaded run');
  const directory = args[args.indexOf('--dir') + 1]; mkdirSync(directory, { recursive: true });
  writeFileSync(join(directory, 'broker-reply.json'), JSON.stringify(entry.envelope)); output('');
}
if (args[0] === 'api' && args[1] === '--method') {
  if (!args.includes('repos/' + state.platform + '/actions/workflows/protected-recovery-invoke.yml/dispatches')) fail('unexpected dispatch target');
  const body = JSON.parse(readFileSync(args[args.indexOf('--input') + 1], 'utf8'));
  if (body.inputs.operation !== 'round-status') fail('unexpected new operation');
  if (state.branchHead !== null) fail('final status dispatched before branch cleanup');
  const id = 100 + state.dispatches++;
  const request = { consumer: body.inputs.target_repository, direction: body.inputs.direction, operation: body.inputs.operation, shard: body.inputs.shard, argument: body.inputs.argument };
  const round = { ...state.round, phaseReady: state.finalReady, blockers: state.finalReady ? [] : ['live binding changed'] };
  state.invocations.push({ run: { id, run_attempt: 1, event: 'workflow_dispatch', head_sha: state.sha, display_title: 'protected-recovery-' + body.inputs.request_nonce, created_at: new Date().toISOString(), path: '.github/workflows/protected-recovery-invoke.yml' }, envelope: { nonce: body.inputs.request_nonce, runId: String(id), runAttempt: '1', request, reply: { round } } });
  output({ workflow_run_id: id });
}
if (args[0] === 'api') {
  const route = args[1];
  if (route === 'repos/owner/consumer/pulls/7') output(state.pr);
  if (route.startsWith('repos/owner/consumer/pulls?')) output([state.pr]);
  if (route === 'repos/' + state.platform + '/git/ref/heads/main') output({ object: { sha: state.sha } });
  if (route.startsWith('repos/' + state.platform + '/actions/workflows/protected-recovery-invoke.yml/runs?')) output({ workflow_runs: state.invocations.map(entry => entry.run) });
  if (/^repos\\/(owner\\/consumer|collinbentley1\\/platform)\\/actions\\/runs\\/[0-9]+$/.test(route)) output({ status: 'completed', run_attempt: 1 });
}
fail('unexpected fake gh command: ' + JSON.stringify(args));
`;

async function fixture() {
  const directory = await mkdtemp(join(tmpdir(), "recovery-operator-cli-"));
  const source = join(directory, "source");
  for (const file of ["protected-recovery/operator.ts", "protected-recovery/orchestrate-deliveries.ts", "protected-recovery/src/model.ts", "tools/ci/workflow-authority.ts"]) {
    await mkdir(dirname(join(source, file)), { recursive: true });
    await copyFile(join(root, file), join(source, file));
  }
  await writeFile(join(source, "protected-recovery/authority.json"), JSON.stringify({ githubOwner: "owner", platformRepository: platform, consumers: [{ repository: "consumer", activeWorkflowSha: sha }] }));
  const bin = join(directory, "bin");
  await mkdir(bin);
  for (const binary of ["gh", "git"]) {
    await writeFile(join(bin, binary), fakeCli);
    await chmod(join(bin, binary), 0o700);
  }
  const templates: Record<string, string> = {};
  for (const file of ["deploy-prod.yml", "deploy-preview.yml", "cleanup-preview.yml", "reconcile-previews.yml"]) templates[file] = (await readFile(join(root, "templates/app/.github/workflows", file), "utf8")).replaceAll("__PLATFORM_SHA__", sha);
  const now = new Date(Date.now() - 60_000).toISOString();
  const round = { ...target, openedAt: now, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), expiredAt: null, members: [member], complete: true, phaseReady: true, blockers: [], owed: [], runs: binding, receipts: binding };
  const state = {
    calls: [] as string[][], templates, sha, platform, round,
    remote: "https://github.com/owner/consumer.git", ref: `refs/heads/${branch}`,
    branchHead: syncSha as string | null, closes: 0, deletes: 0, dispatches: 0, loseCloseResponse: false, finalReady: true,
    pr: { number: 7, state: "open", title: `protected-recovery ${target.round}`, head: { repo: { full_name: target.repository }, ref: branch, sha: syncSha }, base: { repo: { full_name: target.repository }, ref: "main" } },
    invocations: [] as { run: Record<string, unknown>; envelope: Record<string, unknown> }[],
  };
  const statePath = join(directory, "state.json");
  const journals = join(directory, "journals");
  const journal = new Journal(join(journals, "owner-consumer", target.round));
  await mkdir(join(journal.directory, "repo"), { recursive: true });
  for (const [key, value] of Object.entries({ coordinates: target, "pr-commit": prSha, "sync-commit": syncSha, "pr-number": 7, "pr-intent": { branch, title: state.pr.title } })) await journal.write(key, value);
  const save = () => writeFile(statePath, JSON.stringify(state));
  async function run(cleanup = false) {
    await save();
    const child = Bun.spawn([process.execPath, "run", "--no-env-file", join(source, "protected-recovery/orchestrate-deliveries.ts"), ...(cleanup ? ["--cleanup"] : []), "owner/consumer", "CONTROL", "-", "cli-test"], {
      cwd: source, env: { ...process.env, PATH: bin, OPERATOR_FIXTURE_STATE: statePath, PROTECTED_RECOVERY_JOURNAL_DIR: journals }, stdout: "pipe", stderr: "pipe",
    });
    const [code, stdout, stderr] = await Promise.all([child.exited, new Response(child.stdout).text(), new Response(child.stderr).text()]);
    Object.assign(state, JSON.parse(await readFile(statePath, "utf8")));
    return { code, stdout, stderr };
  }
  async function seedCompletedDelivery() {
    for (const [key, value] of Object.entries({ clone: sha, "platform-head": sha, "push-commit": pushSha, "pushed-main": { sha: pushSha, ref: "main" }, "pushed-branch": { sha: prSha, ref: branch }, "pushed-sync": { sha: syncSha, ref: branch }, "dispatch-intent": "e".repeat(64) })) await journal.write(key, value);
    const triggers = [
      ["push-deploy-prod.yml", "deploy-prod.yml", "push", ""], ["push-reconcile-previews.yml", "reconcile-previews.yml", "push", ""],
      ["opened", "deploy-preview.yml", "pull_request_target", `recovery-event-opened-7-${prSha}`], ["synchronize", "deploy-preview.yml", "pull_request_target", `recovery-event-synchronize-7-${syncSha}`],
      ["closed", "cleanup-preview.yml", "pull_request_target", `recovery-event-closed-7-${syncSha}`], ["dispatch", "reconcile-previews.yml", "workflow_dispatch", `recovery-dispatch-${"e".repeat(64)}`], ["schedule", "reconcile-previews.yml", "schedule", ""],
    ];
    for (const [index, trigger] of triggers.entries()) {
      const [key, file, event, title] = trigger;
      await journal.write(`trigger-${key?.replace(/\.yml$/, "")}`, { id: 20 + index, run_attempt: 1, event, head_sha: pushSha, display_title: title, created_at: now, path: `.github/workflows/${file}` });
    }
    for (const [index, stage] of ["open", "bind"].entries()) {
      const request = { consumer: target.consumer, direction: "quarantine", operation: stage === "open" ? "round-open" : "round-bind", shard: "-", argument: stage === "open" ? "CONTROL/cli-test" : canonicalJson({ round: target.round, runs: binding }) };
      const nonce = String(index + 1).repeat(64);
      const id = index + 1;
      await journal.write(`${stage}-intent`, { nonce, after: now, request });
      state.invocations.push({ run: { id, run_attempt: 1, event: "workflow_dispatch", head_sha: sha, display_title: `protected-recovery-${nonce}`, created_at: now, path: ".github/workflows/protected-recovery-invoke.yml" }, envelope: { nonce, runId: String(id), runAttempt: "1", request, reply: { round } } });
    }
  }
  return { directory, state, journal, run, seedCompletedDelivery };
}

test("cleanup resumes a lost close response even with an expired round and no clone", async () => {
  const f = await fixture();
  try {
    f.state.round.expiresAt = "2000-01-01T00:00:00Z";
    f.state.loseCloseResponse = true;
    expect((await f.run(true)).stderr).toContain("simulated lost close response");
    expect(f.state.pr.state).toBe("closed");
    expect(f.state.branchHead).toBe(syncSha);
    const resumed = await f.run(true);
    expect(resumed.code).toBe(0);
    expect(resumed.stdout).toContain("Round completion was not asserted");
    expect(f.state.closes).toBe(1);
    expect(f.state.deletes).toBe(1);
    expect(await f.journal.read("cleanup")).toBeDefined();
    expect(await f.journal.read("complete-0")).toBeUndefined();
    expect(f.state.calls.some(call => call.includes("protected-recovery-invoke.yml"))).toBe(false);
  } finally { await rm(f.directory, { recursive: true, force: true }); }
}, 30_000);

test("cleanup preserves a PR or branch whose current head is no longer owned", async () => {
  for (const changed of ["pr", "branch"] as const) {
    const f = await fixture();
    try {
      if (changed === "pr") f.state.pr.head.sha = "f".repeat(40);
      else f.state.branchHead = "f".repeat(40);
      const result = await f.run(true);
      expect(result.code).toBe(1);
      expect(result.stderr).toContain("changed");
      expect(f.state.deletes).toBe(0);
      if (changed === "pr") expect(f.state.closes).toBe(0);
      expect(await f.journal.read("cleanup")).toBeUndefined();
    } finally { await rm(f.directory, { recursive: true, force: true }); }
  }
}, 30_000);

test("resume completes cleanup before a fresh phase read and never reuses stale readiness", async () => {
  const f = await fixture();
  try {
    await f.seedCompletedDelivery();
    f.state.finalReady = false;
    const first = await f.run();
    expect(first.code).toBe(1);
    expect(first.stderr).toContain("named phase readiness");
    expect(f.state.branchHead).toBeNull();
    expect(await f.journal.read("cleanup")).toBeDefined();
    expect(await f.journal.read("complete-0")).toBeUndefined();
    f.state.finalReady = true;
    const resumed = await f.run();
    expect(resumed.code).toBe(0);
    expect(resumed.stdout).toContain("current CONTROL evidence and verified PR/branch cleanup");
    expect(f.state.dispatches).toBe(2);
    expect(f.state.closes).toBe(1);
    expect(f.state.deletes).toBe(1);
    expect(await f.journal.read("complete-1")).toBeDefined();
  } finally { await rm(f.directory, { recursive: true, force: true }); }
}, 30_000);
