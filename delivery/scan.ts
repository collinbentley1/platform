import { google } from "./google.ts";
import { imageName, type Project } from "./catalog.ts";

export type Occurrence = {
  name: string; resourceUri: string; noteName: string; kind: string;
  discovery?: { analysisStatus?: string; continuousAnalysis?: string; analysisError?: unknown[]; analysisStatusError?: { code?: number }; analysisCompleted?: { analysisType?: string[] } };
  vulnerability?: { effectiveSeverity?: string; severity?: string; packageIssue?: Array<{ affectedPackage?: string }> };
};
export function scanDecision(rows: readonly Occurrence[], resource: string): { ready: boolean; blocking: string[] } {
  if (rows.some(row => row.resourceUri !== resource)) throw new Error("Vulnerability inventory is bound to a different image.");
  const discovery = rows.filter(row => row.kind === "DISCOVERY");
  if (discovery.some(row => ["FINISHED_FAILED", "FINISHED_UNSUPPORTED"].includes(row.discovery?.analysisStatus ?? ""))) throw new Error("Managed scanning failed or does not support this image.");
  const ready = discovery.length > 0 && discovery.every(row => ["FINISHED_SUCCESS", "COMPLETE"].includes(row.discovery?.analysisStatus ?? "") && row.discovery?.continuousAnalysis === "ACTIVE" && !(row.discovery.analysisError?.length) && !row.discovery.analysisStatusError?.code);
  const blocking = rows.filter(row => row.kind === "SECRET" || row.kind === "VULNERABILITY").filter(row => {
    if (row.kind === "SECRET") return true;
    const severity = row.vulnerability?.effectiveSeverity ?? row.vulnerability?.severity;
    return !["MINIMAL", "LOW", "MEDIUM"].includes(severity ?? "");
  }).map(row => row.noteName.split("/").at(-1) ?? "unknown-advisory");
  return { ready, blocking };
}

export async function scanImage(app: Project, digest: string, timeoutMs = 15 * 60_000): Promise<void> {
  if (!/^sha256:[a-f0-9]{64}$/.test(digest)) throw new Error("Invalid image digest.");
  const resource = `https://${imageName(app)}@${digest}`;
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    const rows: Occurrence[] = []; let page = "";
    for (let count = 0; count < 50; count++) {
      const query = new URLSearchParams({ filter: `resourceUrl="${resource}"`, pageSize: "1000", ...(page ? { pageToken: page } : {}) });
      const result = await google<{ occurrences?: Occurrence[]; nextPageToken?: string }>(`https://containeranalysis.googleapis.com/v1/projects/${app.project}/occurrences?${query}`);
      rows.push(...(result.occurrences ?? [])); page = result.nextPageToken ?? "";
      if (!page) break;
      if (count === 49) throw new Error("Vulnerability inventory exceeds its pagination bound.");
    }
    const decision = scanDecision(rows, resource);
    if (decision.blocking.length) throw new Error(`Managed scanning blocked deployment: ${decision.blocking.join(", ")}`);
    if (decision.ready) { console.info(JSON.stringify({ event: "image-scan-passed", app: app.name, digest })); return; }
    await Bun.sleep(15_000);
  }
  throw new Error("A complete, active managed vulnerability scan was not available before deployment.");
}
