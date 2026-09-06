import { execFile } from "node:child_process";
import { randomBytes } from "node:crypto";
import { homedir } from "node:os";
import { mkdir, readFile, rm } from "node:fs/promises";
import { join } from "node:path";
import { promisify } from "node:util";
import { canonicalJson, type RoundRuns } from "./src/model.ts";
import { callerPins, callerUses, completeRound, coordinates, exact, Journal, memberTrigger, object, ownedPullRequest, parseRuns, readJsonFile, replyEnvelope, roundReply, selectRun, string, strings, type Invocation, type Run } from "./operator.ts";

const execute = promisify(execFile);
const root = join(import.meta.dir, "..");
async function command(binary: string, args: readonly string[], cwd = root): Promise<string> {
  const result = await execute(binary, [...args], { cwd, encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 10 * 60 * 1000, env: { ...process.env, GIT_TERMINAL_PROMPT: "0", GH_PROMPT_DISABLED: "1" } });
  return result.stdout.trim();
}
async function api(path: string): Promise<unknown> { return JSON.parse(await command("gh", ["api", path])); }
const pause = () => Bun.sleep(5000);
const nonce = () => randomBytes(32).toString("hex");

async function main(): Promise<void> {
  const args = Bun.argv.slice(2);
  const cleanupOnly = args[0] === "--cleanup";
  const target = coordinates(cleanupOnly ? args.slice(1) : args);
  const authority = object(JSON.parse(await readFile(join(import.meta.dir, "authority.json"), "utf8")));
  exact(target.repository, `${string(authority.githubOwner)}/${target.consumer}`, "consumer repository owner");
  const platform = string(authority.platformRepository);
  const consumers = authority.consumers;
  if (!Array.isArray(consumers)) throw new Error("authority has no consumers");
  const consumer = consumers.map(object).find((item) => item.repository === target.consumer);
  if (!consumer) throw new Error("consumer is not recorded in authority");
  const pins = [consumer.activeWorkflowSha, consumer.transitionWorkflowSha].filter((pin): pin is string => typeof pin === "string" && /^[0-9a-f]{40}$/.test(pin));

  const directory = join(process.env.PROTECTED_RECOVERY_JOURNAL_DIR ?? join(homedir(), ".local/state/protected-recovery"), target.repository.replace("/", "-"), target.round);
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const lock = join(directory, "operator.lock");
  await mkdir(lock, { mode: 0o700 }).catch(() => { throw new Error(`operator lock exists at ${lock}; verify its process has stopped before removing this lock`); });
  const journal = new Journal(directory);
  try {
    if (cleanupOnly) exact(await journal.read("coordinates"), target, "recorded cleanup coordinates");
    else await journal.write("coordinates", target);
    process.stdout.write(`Operator evidence: ${directory}\n`);
    await command("gh", ["auth", "status"]);
    const repo = join(directory, "repo");
    const branch = `protected-recovery/delivery-${target.round}`;
    const title = `protected-recovery ${target.round}`;
    const remote = `https://github.com/${target.repository}.git`;
    async function recordedHeads(): Promise<string[]> {
      const heads = [await journal.read("pr-commit"), await journal.read("sync-commit")].filter((value): value is string => typeof value === "string" && /^[0-9a-f]{40}$/.test(value));
      if (heads.length === 0 && await journal.read("pr-intent") !== undefined) throw new Error("PR intent has no recorded owned head");
      return heads;
    }
    async function closePr(number: number, heads: readonly string[]): Promise<void> {
      const expected = { repository: target.repository, branch, title, heads };
      const current = ownedPullRequest(await api(`repos/${target.repository}/pulls/${number}`), expected);
      exact(current.number, number, "recorded pull request number");
      if (current.state === "open") await command("gh", ["pr", "close", String(number), "--repo", target.repository]);
      const final = ownedPullRequest(await api(`repos/${target.repository}/pulls/${number}`), expected);
      exact(final.state, "closed", "closed recovery pull request");
      await journal.write("pr-closed", number);
    }
    async function cleanup(): Promise<void> {
      const heads = await recordedHeads();
      const savedNumber = await journal.read("pr-number");
      let number: number | null = null;
      if (savedNumber !== undefined) {
        if (!Number.isSafeInteger(savedNumber) || Number(savedNumber) < 1) throw new Error("invalid recorded PR number");
        number = Number(savedNumber);
      } else {
        const found = await api(`repos/${target.repository}/pulls?state=all&head=${encodeURIComponent(`${string(authority.githubOwner)}:${branch}`)}&base=main&per_page=100`);
        if (!Array.isArray(found) || found.length > 1) throw new Error("ambiguous recovery cleanup pull request");
        if (found.length === 1) {
          number = ownedPullRequest(found[0], { repository: target.repository, branch, title, heads }).number;
          await journal.write("pr-number", number);
        } else if (await journal.read("pr-intent") !== undefined) throw new Error("PR creation intent is unresolved; reconcile it before claiming cleanup");
      }
      if (number !== null) await closePr(number, heads);
      const ref = `refs/heads/${branch}`;
      const listing = await command("git", ["ls-remote", "--heads", remote, ref]);
      if (listing) {
        const fields = listing.split(/\s/);
        if (fields.length !== 2 || fields[1] !== ref || !heads.includes(fields[0]!)) throw new Error("recovery branch changed; preserve it for manual review");
        await command("git", ["push", "--quiet", `--force-with-lease=${ref}:${fields[0]}`, remote, `:${ref}`]);
      }
      exact(await command("git", ["ls-remote", "--heads", remote, ref]), "", "final branch cleanup");
      await journal.write("cleanup", { round: target.round, pullRequest: number, branch });
    }
    if (cleanupOnly) {
      await cleanup();
      await journal.write("cleanup-only", { round: target.round });
      process.stdout.write(`Recorded PR/branch cleanup verified for ${target.round}. Round completion was not asserted.\n`);
      return;
    }
    if (await journal.read("cleanup-only") !== undefined) throw new Error("this round was abandoned for cleanup; retain its evidence and use a new label after broker reconciliation");
    if (pins.length === 0) throw new Error("consumer workflow pins are not recorded");

    if (await journal.read("clone") === undefined) {
      await rm(repo, { recursive: true, force: true });
      await command("git", ["clone", "--quiet", "--branch", "main", `https://github.com/${target.repository}.git`, repo]);
      await command("git", ["config", "user.name", "protected-recovery"], repo);
      await command("git", ["config", "user.email", "protected-recovery@users.noreply.github.com"], repo);
      await journal.write("clone", await command("git", ["rev-parse", "HEAD"], repo));
    }
    const initialHead = string(await journal.read("clone"));
    const callerBindings: Record<string, Record<string, string>> = {};
    for (const file of Object.keys(callerUses)) {
      const content = await command("git", ["show", `${initialHead}:.github/workflows/${file}`], repo);
      callerBindings[file] = callerPins(content, file, platform, pins);
    }
    await journal.write("caller-pins", callerBindings);
    const platformHead = await savedString("platform-head", async () => string(object(object(await api(`repos/${platform}/git/ref/heads/main`)).object).sha));

    async function savedString(key: string, make: () => Promise<string>): Promise<string> {
      const old = await journal.read(key);
      if (old !== undefined) return string(old);
      const value = await make(); await journal.write(key, value); return value;
    }
    async function runs(repository: string, file: string, event: string, after: string): Promise<Run[]> {
      const query = `repos/${repository}/actions/workflows/${file}/runs?event=${event}&created=${encodeURIComponent(`>=${after}`)}&per_page=100`;
      const found: Run[] = [];
      for (let page = 1; page <= 10; page += 1) {
        const batch = parseRuns(await api(`${query}&page=${page}`));
        found.push(...batch);
        if (batch.length < 100) return found;
      }
      throw new Error("workflow run listing exceeds the bounded selection budget");
    }
    async function dispatch(stage: string, repository: string, file: string, inputs: Readonly<Record<string, string>>): Promise<void> {
      const body = join(directory, `${stage}-dispatch.json`);
      await Bun.write(body, canonicalJson({ ref: "main", inputs }));
      const response = object(JSON.parse(await command("gh", ["api", "--method", "POST", "-H", "X-GitHub-Api-Version: 2026-03-10", `repos/${repository}/actions/workflows/${file}/dispatches`, "--input", body])));
      if (!Number.isSafeInteger(response.workflow_run_id) || Number(response.workflow_run_id) < 1) throw new Error("dispatch response has no exact workflow run ID");
      await journal.write(`${stage}-dispatch-run`, String(response.workflow_run_id));
    }
    async function resolveRun(repository: string, file: string, event: string, head: string, title: string | null, after: string, minutes = 5): Promise<Run> {
      const end = Date.now() + minutes * 60_000;
      do {
        const found = selectRun(await runs(repository, file, event, after), { path: `.github/workflows/${file}`, event, head, title, after });
        if (found) return found;
        await pause();
      } while (Date.now() < end);
      throw new Error(`no exact run for ${file}/${event}; retained pending intent will not be dispatched again`);
    }
    async function watch(repository: string, run: Run): Promise<void> {
      // A quarantine deliberately fails cloud exchange after delivering. Only
      // broker receipts, never workflow success, establish the requested phase.
      await command("gh", ["run", "watch", run.id, "--repo", repository]);
      const current = object(await api(`repos/${repository}/actions/runs/${run.id}`));
      exact(String(current.run_attempt), "1", "watched run attempt");
      exact(current.status, "completed", "watched run status");
    }
    async function invoke(stage: string, operation: string, shard: string, argument: string): Promise<Record<string, unknown>> {
      const request: Invocation = { consumer: target.consumer, direction: "quarantine", operation, shard, argument };
      const prior = await journal.read(`${stage}-intent`);
      const intent = prior === undefined ? { nonce: nonce(), after: new Date(Math.floor(Date.now() / 1000) * 1000).toISOString(), request } : object(prior);
      exact(intent.request, request, "journal invocation request");
      if (prior === undefined) {
        exact(object(object(await api(`repos/${platform}/git/ref/heads/main`)).object).sha, platformHead, "current invoke workflow commit");
        await journal.write(`${stage}-intent`, intent);
        await dispatch(stage, platform, "protected-recovery-invoke.yml", { request_nonce: string(intent.nonce), target_repository: request.consumer, direction: request.direction, operation, shard, argument });
      }
      const selected = await resolveRun(platform, "protected-recovery-invoke.yml", "workflow_dispatch", platformHead, `protected-recovery-${string(intent.nonce)}`, string(intent.after));
      const dispatchedRun = await journal.read(`${stage}-dispatch-run`);
      if (dispatchedRun !== undefined) exact(selected.id, dispatchedRun, "dispatch response run ID");
      await journal.write(`${stage}-run`, selected);
      await watch(platform, selected);
      const replyDirectory = join(directory, `${stage}-reply`);
      await rm(replyDirectory, { recursive: true, force: true });
      await command("gh", ["run", "download", selected.id, "--repo", platform, "--name", "broker-reply", "--dir", replyDirectory]);
      const reply = replyEnvelope(await readJsonFile(join(replyDirectory, "broker-reply.json")), string(intent.nonce), selected.id, request);
      await journal.write(`${stage}-reply`, reply);
      return roundReply(reply, target);
    }

    let round = await invoke("open", "round-open", target.shard ?? "-", `${target.phase}/${target.label}`);
    const members = strings(round.members);
    const triggerForMember = Object.fromEntries(members.map((member) => [member, memberTrigger(member, target.repository, callerBindings)]));
    const openedAt = new Date(Math.floor(Date.parse(string(round.openedAt)) / 1000) * 1000).toISOString();
    const pushSha = await savedString("push-commit", async () => {
      return command("git", ["commit-tree", `${initialHead}^{tree}`, "-p", initialHead, "-m", `protected-recovery: ${target.round} push`], repo);
    });
    async function push(key: string, sha: string, ref: string): Promise<void> {
      if (await journal.read(key) !== undefined) return;
      await command("git", ["push", "--quiet", "origin", `${sha}:refs/heads/${ref}`], repo);
      const actual = await command("git", ["ls-remote", "--heads", "origin", `refs/heads/${ref}`], repo);
      exact(actual.split(/\s/)[0], sha, "pushed commit");
      await journal.write(key, { sha, ref });
    }
    // Pushing an already accepted SHA is a no-op after a crash. A moved main
    // fails its fast-forward check; it is never force-reset by this operator.
    await push("pushed-main", pushSha, "main");
    const triggerRuns: Record<string, { runId: string; runAttempt: string }> = {};
    async function recordRun(key: string, file: string, event: string, head: string, title: string | null, minutes = 5): Promise<void> {
      const stage = `trigger-${key.replace(/\.yml$/, "")}`;
      const saved = await journal.read(stage);
      const selected = saved === undefined ? await resolveRun(target.repository, file, event, head, title, openedAt, minutes) : parseRuns({ workflow_runs: [object(saved)] })[0]!;
      const identity = { id: Number(selected.id), run_attempt: Number(selected.attempt), event: selected.event, head_sha: selected.head, display_title: selected.title, created_at: selected.created, path: selected.path };
      await journal.write(stage, identity);
      await watch(target.repository, selected);
      triggerRuns[key] = { runId: selected.id, runAttempt: selected.attempt };
    }
    await recordRun("push-deploy-prod.yml", "deploy-prod.yml", "push", pushSha, null);
    await recordRun("push-reconcile-previews.yml", "reconcile-previews.yml", "push", pushSha, null);
    const prSha = await savedString("pr-commit", () => command("git", ["commit-tree", `${initialHead}^{tree}`, "-p", pushSha, "-m", `protected-recovery: ${target.round} opened`], repo));
    await push("pushed-branch", prSha, branch);
    async function findPr(): Promise<number | null> {
      const found = await api(`repos/${target.repository}/pulls?state=all&head=${encodeURIComponent(`${string(authority.githubOwner)}:${branch}`)}&base=main&per_page=100`);
      if (!Array.isArray(found) || found.length > 1) throw new Error("ambiguous recovery pull request");
      if (found.length === 0) return null;
      return ownedPullRequest(found[0], { repository: target.repository, branch, title, heads: await recordedHeads() }).number;
    }
    let number = await findPr();
    if (number === null) {
      if (await journal.read("pr-intent") !== undefined) throw new Error("pull request creation is unresolved; inspect saved intent before continuing");
      await journal.write("pr-intent", { branch, title });
      const body = join(directory, "pr-body.txt");
      await Bun.write(body, `Delivery events for protected recovery round ${target.round}. The operator closes this pull request and verifies branch removal.\n`);
      await command("gh", ["pr", "create", "--repo", target.repository, "--base", "main", "--head", branch, "--title", title, "--body-file", body]);
      number = await findPr();
    }
    if (number === null) throw new Error("pull request creation has no authoritative readback");
    await journal.write("pr-number", number);
    await recordRun("opened", "deploy-preview.yml", "pull_request_target", pushSha, `recovery-event-opened-${number}-${prSha}`);
    const syncSha = await savedString("sync-commit", () => command("git", ["commit-tree", `${initialHead}^{tree}`, "-p", prSha, "-m", `protected-recovery: ${target.round} synchronize`], repo));
    await push("pushed-sync", syncSha, branch);
    await recordRun("synchronize", "deploy-preview.yml", "pull_request_target", pushSha, `recovery-event-synchronize-${number}-${syncSha}`);
    await closePr(number, [syncSha]);
    await recordRun("closed", "cleanup-preview.yml", "pull_request_target", pushSha, `recovery-event-closed-${number}-${syncSha}`);
    const priorDispatch = await journal.read("dispatch-intent");
    const dispatchNonce = priorDispatch === undefined ? nonce() : string(priorDispatch);
    if (priorDispatch === undefined) {
      await journal.write("dispatch-intent", dispatchNonce);
      exact(object(object(await api(`repos/${target.repository}/git/ref/heads/main`)).object).sha, pushSha, "dispatch main commit");
      await dispatch("consumer", target.repository, "reconcile-previews.yml", { delivery_nonce: dispatchNonce });
    }
    await recordRun("dispatch", "reconcile-previews.yml", "workflow_dispatch", pushSha, `recovery-dispatch-${dispatchNonce}`);
    const dispatchedConsumerRun = await journal.read("consumer-dispatch-run");
    if (dispatchedConsumerRun !== undefined) exact(triggerRuns.dispatch?.runId, dispatchedConsumerRun, "consumer dispatch response run ID");
    process.stdout.write("Waiting for the scheduled reconcile delivery at the recorded main commit.\n");
    await recordRun("schedule", "reconcile-previews.yml", "schedule", pushSha, null, 100);
    const boundRuns: Record<string, { runId: string; runAttempt: string }> = {};
    for (const [member, trigger] of Object.entries(triggerForMember)) {
      const run = triggerRuns[trigger];
      if (!run) throw new Error(`missing trigger ${trigger}`);
      boundRuns[member] = run;
    }
    const runsBinding: RoundRuns = boundRuns;
    await journal.write("bound-runs", runsBinding);
    round = await invoke("bind", "round-bind", "-", canonicalJson({ round: target.round, runs: runsBinding }));
    for (let poll = 0; !round.complete && poll < 30; poll += 1) {
      await pause();
      round = await invoke(`status-${poll}`, "round-status", "-", target.round);
    }
    await cleanup();
    // Cleanup has its own durable result. A new broker read afterward must
    // still establish current phase readiness, including on every restart.
    let check = 0;
    while (await journal.read(`final-${check}-intent`) !== undefined) check += 1;
    round = await invoke(`final-${check}`, "round-status", "-", target.round);
    completeRound(round, runsBinding);
    await journal.write(`complete-${check}`, { round: target.round, pushSha, pullRequest: number, runs: runsBinding, checkedAt: new Date().toISOString() });
    process.stdout.write(`Round ${target.round} has current ${target.phase} evidence and verified PR/branch cleanup. Main commit ${pushSha} remains recorded.\n`);
  } finally { await rm(lock, { recursive: true }); }
}

if (import.meta.main) main().catch((error: unknown) => {
  process.stderr.write(`${error instanceof Error ? error.message : "operator failed"}\nTrigger and cleanup debt remain in the durable journal. Use --cleanup with the same coordinates to reconcile recorded PR/branch debt without reading the broker round.\n`);
  process.exitCode = 1;
});
