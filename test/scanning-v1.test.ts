import { test, expect } from "bun:test";
import { scanDecision, type Occurrence } from "../delivery/scan.ts";
const resource = "https://us-east4-docker.pkg.dev/example/site/application@sha256:" + "a".repeat(64);
const base: Occurrence = { name: "discovery", resourceUri: resource, noteName: "projects/goog-analysis/notes/discovery", kind: "DISCOVERY", discovery: { analysisStatus: "FINISHED_SUCCESS", continuousAnalysis: "ACTIVE" } };
test("missing, incomplete, disabled, or failed scanning cannot become a zero-finding success", () => {
  expect(scanDecision([], resource).ready).toBe(false);
  expect(scanDecision([{ ...base, discovery: { ...base.discovery, analysisStatus: "SCANNING" } }], resource).ready).toBe(false);
  expect(scanDecision([{ ...base, discovery: { ...base.discovery, continuousAnalysis: "INACTIVE" } }], resource).ready).toBe(false);
  expect(() => scanDecision([{ ...base, discovery: { analysisStatus: "FINISHED_FAILED" } }], resource)).toThrow();
  expect(scanDecision([base], resource)).toEqual({ ready: true, blocking: [] });
});
test("high, critical, and unknown findings block regardless of fix availability", () => {
  for (const severity of ["HIGH", "CRITICAL", "SEVERITY_UNSPECIFIED"]) {
    expect(scanDecision([base, { ...base, kind: "VULNERABILITY", noteName: "projects/goog-vulnz/notes/advisory", vulnerability: { effectiveSeverity: severity } }], resource).blocking).toEqual(["advisory"]);
  }
  expect(() => scanDecision([base], resource + "other")).toThrow("different image");
});
