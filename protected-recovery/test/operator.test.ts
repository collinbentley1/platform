import { describe, expect, test } from "bun:test";
import { mkdtemp, readFile, rm, stat } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { callerPins, completeRound, coordinates, Journal, memberTrigger, ownedPullRequest, parseRuns, replyEnvelope, roundReply, selectRun, timestamp } from "../operator.ts";

const target = coordinates(["owner/consumer", "REVOCATION", "session-1", "test"]);
const nonce = "f".repeat(64);
const sha = "a".repeat(40);
const request = { consumer: "consumer", direction: "quarantine", operation: "round-status", shard: "-", argument: target.round } as const;
const round = () => ({ ...target, expiresAt: new Date(Date.now() + 3_600_000).toISOString(), expiredAt: null, members: ["member"], complete: true, phaseReady: true, blockers: [], owed: [], runs: { member: { runId: "42", runAttempt: "1" } }, receipts: { member: { runId: "42", runAttempt: "1" } } });
const envelope = () => ({ nonce, runId: "42", runAttempt: "1", request, reply: { round: round() } });
const rawRun = (overrides = {}) => ({ id: 42, run_attempt: 1, event: "workflow_dispatch", head_sha: sha, display_title: `protected-recovery-${nonce}`, created_at: "2026-09-05T12:00:00Z", path: ".github/workflows/protected-recovery-invoke.yml", ...overrides });
const expectedRun = { path: ".github/workflows/protected-recovery-invoke.yml", event: "workflow_dispatch", head: sha, title: `protected-recovery-${nonce}`, after: "2026-09-05T12:00:00Z" };

describe("durable delivery operator", () => {
  test("selects the exact nonce while another operator dispatches later in the same second", () => {
    const runs = parseRuns({ workflow_runs: [rawRun(), rawRun({ id: 43, display_title: "protected-recovery-other" })] });
    expect(selectRun(runs, expectedRun)?.id).toBe("42");
    expect(selectRun(runs, { ...expectedRun, head: "b".repeat(40) })).toBeNull();
    expect(selectRun(runs, { ...expectedRun, event: "push" })).toBeNull();
  });
  test("ambiguous matching dispatches and reruns cannot count", () => {
    expect(() => selectRun(parseRuns({ workflow_runs: [rawRun(), rawRun({ id: 43 })] }), expectedRun)).toThrow("ambiguous");
    expect(() => selectRun(parseRuns({ workflow_runs: [rawRun({ run_attempt: 2 })] }), expectedRun)).toThrow("rerun");
  });
  test("malformed dates and nonpositive run identities fail before selection", () => {
    for (const value of ["invalid", "2026-02-31T12:00:00Z", "2026-09-05", "2026-09-05T12:00:00+01:00"]) expect(() => timestamp(value)).toThrow();
    for (const change of [{ id: 0 }, { run_attempt: -1 }, { created_at: "invalid" }, { head_sha: "short" }]) expect(() => parseRuns({ workflow_runs: [rawRun(change)] })).toThrow();
    expect(() => selectRun(parseRuns({ workflow_runs: [rawRun()] }), { ...expectedRun, after: "invalid" })).toThrow();
    expect(() => parseRuns({ workflow_runs: Array.from({ length: 101 }, () => rawRun()) })).toThrow("bounded");
  });
  test("cleanup refuses another repository, ref, base, or changed PR head", () => {
    const expected = { repository: "owner/consumer", branch: "protected-recovery/delivery-one", title: "owned recovery", heads: [sha] };
    const pr = { number: 7, state: "open", title: expected.title, head: { repo: { full_name: expected.repository }, ref: expected.branch, sha }, base: { repo: { full_name: expected.repository }, ref: "main" } };
    expect(ownedPullRequest(pr, expected)).toEqual({ number: 7, state: "open", head: sha });
    for (const change of [{ head: { ...pr.head, sha: "b".repeat(40) } }, { head: { ...pr.head, ref: "someone-else" } }, { head: { ...pr.head, repo: { full_name: "owner/another" } } }, { base: { ...pr.base, ref: "release" } }]) expect(() => ownedPullRequest({ ...pr, ...change }, expected)).toThrow();
  });
  test("the downloaded artifact binds nonce, run, attempt, and every request input", () => {
    expect(replyEnvelope(envelope(), nonce, "42", request).round).toBeDefined();
    for (const change of [{ nonce: "0".repeat(64) }, { runId: "43" }, { runAttempt: "2" }, { request: { ...request, consumer: "other" } }, { request: { ...request, argument: "0".repeat(64) } }]) {
      expect(() => replyEnvelope({ ...envelope(), ...change }, nonce, "42", request)).toThrow();
    }
  });
  test("every response must identify the saved phase, shard, consumer, label, and round", () => {
    expect(roundReply({ round: round() }, target).complete).toBe(true);
    for (const change of [{ round: "0".repeat(64) }, { shard: "another-session" }, { consumer: "another" }, { phase: "HORIZON" }, { label: "another" }, { expiresAt: "invalid" }, { expiresAt: "2000-01-01T00:00:00Z" }, { expiredAt: "2026-09-05T12:00:00Z" }]) {
      expect(() => roundReply({ round: { ...round(), ...change } }, target)).toThrow();
    }
  });
  test("completion needs current named-phase readiness and the exact receipt set", () => {
    const value = round();
    expect(() => completeRound(value, value.runs)).not.toThrow();
    for (const change of [{ phaseReady: false }, { blockers: ["live binding changed"] }, { owed: ["member"] }, { receipts: { member: { runId: "43", runAttempt: "1" } } }, { runs: null }, { receipts: {} }]) {
      expect(() => completeRound({ ...value, ...change }, value.runs)).toThrow();
    }
  });
  test("round-derived branch identity cannot collide across shards or phases", () => {
    const horizon = coordinates(["owner/consumer", "HORIZON", "session-1", "test"]);
    const second = coordinates(["owner/consumer", "REVOCATION", "session-2", "test"]);
    expect(new Set([target.round, horizon.round, second.round]).size).toBe(3);
    expect(() => coordinates(["owner/consumer", "CONTROL", "session-1", "test"])).toThrow();
  });
  test("missing platform calls and unrecorded pins fail preflight", async () => {
    const platform = "collinbentley1/platform";
    const content = (await readFile(join(import.meta.dir, "../../templates/app/.github/workflows/deploy-prod.yml"), "utf8")).replaceAll("__PLATFORM_SHA__", sha);
    expect(callerPins(content, "deploy-prod.yml", platform, [sha])).toEqual({ "deploy-prod.yml": sha, "infrastructure.yml": sha });
    expect(() => callerPins("jobs: {}", "deploy-prod.yml", platform, [sha])).toThrow();
    expect(() => callerPins(content, "deploy-prod.yml", platform, ["b".repeat(40)])).toThrow();
    expect(() => callerPins(content.replace(/    uses: .*infrastructure.*\n/, ""), "deploy-prod.yml", platform, [sha])).toThrow();
  });
  test("caller preflight parses correlation, lifecycle events, and dispatch inputs", async () => {
    for (const file of ["deploy-preview.yml", "cleanup-preview.yml", "reconcile-previews.yml"]) {
      const content = (await readFile(join(import.meta.dir, "../../templates/app/.github/workflows", file), "utf8")).replaceAll("__PLATFORM_SHA__", sha);
      expect(() => callerPins(content, file, "collinbentley1/platform", [sha])).not.toThrow();
      expect(() => callerPins(content.replace(/^run-name:/m, "# run-name:"), file, "collinbentley1/platform", [sha])).toThrow();
      if (file === "reconcile-previews.yml") {
        expect(() => callerPins(content.replace("delivery_nonce:", "unrelated_input:"), file, "collinbentley1/platform", [sha])).toThrow();
        expect(() => callerPins(content.replace("    uses:", "    with:\n      leak: ${{ toJSON(inputs) }}\n    uses:"), file, "collinbentley1/platform", [sha])).toThrow("job shape");
        expect(() => callerPins(content.replace("    uses:", "    env:\n      LEAK: ${{ toJSON(github.event.inputs) }}\n    uses:"), file, "collinbentley1/platform", [sha])).toThrow("job shape");
        expect(() => callerPins(content.replace("  workflow_dispatch:", "  pull_request:\n  workflow_dispatch:"), file, "collinbentley1/platform", [sha])).toThrow("event set");
        expect(() => callerPins(content.replace("17 * * * *", "17 1 * * *"), file, "collinbentley1/platform", [sha])).toThrow("hourly");
        expect(() => callerPins(content.replace("  push:", "  unused_push:"), file, "collinbentley1/platform", [sha])).toThrow();
      } else {
        const event = file === "cleanup-preview.yml" ? "closed" : "synchronize";
        expect(() => callerPins(content.replace(`      - ${event}\n`, ""), file, "collinbentley1/platform", [sha])).toThrow();
      }
    }
  });
  test("member bindings distinguish opened and synchronize cleanup callers and exact pins", () => {
    const pins = { "deploy-preview.yml": { "deploy-preview.yml": sha, "cleanup-preview.yml": sha } };
    const member = (workflow: string, pin = sha) => `principalSet://iam.googleapis.com/pool/attribute.authority/owner/consumer/.github/workflows/deploy-preview.yml@refs/heads/main:collinbentley1/platform/.github/workflows/${workflow}@${pin}:${pin}:preview-cloud:pull_request_target`;
    expect(memberTrigger(member("deploy-preview.yml"), "owner/consumer", pins)).toBe("opened");
    expect(memberTrigger(member("cleanup-preview.yml"), "owner/consumer", pins)).toBe("synchronize");
    expect(() => memberTrigger(member("cleanup-preview.yml", "b".repeat(40)), "owner/consumer", pins)).toThrow("finish the pin transition");
  });
  test("journal survives a new operator object and refuses a second interpretation of intent", async () => {
    const directory = await mkdtemp(join(tmpdir(), "recovery-operator-test-"));
    try {
      const first = new Journal(directory);
      await first.write("dispatch-intent", { nonce, request });
      const resumed = new Journal(directory);
      expect(await resumed.read("dispatch-intent")).toEqual({ nonce, request });
      await resumed.write("dispatch-intent", { nonce, request });
      await expect(resumed.write("dispatch-intent", { nonce: "other", request })).rejects.toThrow("immutable");
      expect((await stat(join(directory, "dispatch-intent.json"))).mode & 0o077).toBe(0);
    } finally { await rm(directory, { recursive: true, force: true }); }
  });
});
