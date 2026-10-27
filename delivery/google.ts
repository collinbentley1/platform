import { command } from "./process.ts";
import { readText } from "../runtime/http.ts";

const hosts = new Set(["artifactregistry.googleapis.com", "containeranalysis.googleapis.com", "run.googleapis.com", "storage.googleapis.com", "identitytoolkit.googleapis.com", "apikeys.googleapis.com", "firestore.googleapis.com", "monitoring.googleapis.com", "recaptchaenterprise.googleapis.com"]);
export class GoogleError extends Error { constructor(readonly status: number) { super(`Google API request failed (${status}).`); } }
export async function accessToken(): Promise<string> { return Bun.env.GOOGLE_OAUTH_ACCESS_TOKEN ?? await command(["gcloud", "auth", "print-access-token"], { quiet: true }); }
export async function google<T>(address: string, method = "GET", body?: unknown, quotaProject?: string): Promise<T> {
  const url = new URL(address);
  if(quotaProject && !/^[a-z][a-z0-9-]{4,28}[a-z0-9]$/.test(quotaProject)) throw new Error("Invalid quota project.");
  if (url.protocol !== "https:" || !hosts.has(url.hostname) || url.username || url.password) throw new Error("Invalid Google API destination.");
  const response = await fetch(url, { method, headers: { Authorization: `Bearer ${await accessToken()}`, "Content-Type": "application/json", ...(quotaProject?{"X-Goog-User-Project":quotaProject}:{}) }, ...(body === undefined ? {} : { body: JSON.stringify(body) }), redirect: "error", signal: AbortSignal.timeout(30_000) });
  if (!response.ok) throw new GoogleError(response.status);
  if (response.status === 204) return undefined as T;
  const value = await readText(response, 8_388_608);
  return value ? JSON.parse(value) as T : undefined as T;
}
export async function operation(name: string): Promise<void> {
  if (!/^projects\/[a-z0-9-]+\/locations\/[a-z0-9-]+\/operations\/[a-zA-Z0-9-]+$/.test(name)) throw new Error("Invalid Cloud Run operation.");
  const deadline = Date.now() + 10 * 60_000;
  while (Date.now() < deadline) {
    const value = await google<{ done?: boolean; error?: unknown }>(`https://run.googleapis.com/v2/${name}`);
    if (value.error) throw new Error("Cloud Run operation failed.");
    if (value.done) return;
    await Bun.sleep(3000);
  }
  throw new Error("Cloud Run operation did not settle before its deadline.");
}
