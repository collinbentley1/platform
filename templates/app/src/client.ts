type Note = { id: string; title: string; createdAt: string };
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const status = element<HTMLParagraphElement>("status");
let pendingNote: { id: string; title: string } | undefined;
function announce(message: string, error = false) { status.textContent = message; status.dataset.error = String(error); }
async function api(path: string, init: RequestInit = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...init, headers: { "Content-Type": "application/json", ...Object.fromEntries(new Headers(init.headers)) }, signal: AbortSignal.timeout(15_000) });
  const body = await response.json() as { error?: string; notes?: Note[]; development?: boolean; preview?: boolean; user?: { emailVerified?: boolean } };
  if (!response.ok) { if (response.status === 401) signedIn(false); throw new Error(body.error ?? "Please try again."); }
  return body;
}
function signedIn(yes: boolean) { element("sign-in").hidden = yes; element("workspace").hidden = !yes; if (!yes) { element("notes").replaceChildren(); pendingNote = undefined; } }
async function refresh() {
  const { notes } = await api("/api/notes") as { notes: Note[] };
  element("notes").replaceChildren(); element("empty").hidden = notes.length !== 0;
  for (const note of notes) {
    const li = document.createElement("li"); const title = document.createElement("span"); title.textContent = note.title;
    const button = document.createElement("button"); button.type = "button"; button.textContent = "Delete"; button.setAttribute("aria-label", `Delete ${note.title}`);
    button.addEventListener("click", () => { void action(button, async () => { await api(`/api/notes/${note.id}`, { method: "DELETE" }); await refresh(); announce("Note deleted."); }); });
    li.append(title, button); element("notes").append(li);
  }
}
async function action(button: HTMLButtonElement, run: () => Promise<void>) {
  button.disabled = true; announce("Working…");
  try { await run(); } catch (error) { announce(error instanceof Error ? error.message : "Please try again.", true); } finally { button.disabled = false; }
}
element<HTMLFormElement>("login-form").addEventListener("submit", event => {
  event.preventDefault(); const form = event.currentTarget as HTMLFormElement;
  void action(form.querySelector("button")!, async () => {
    await api((event as SubmitEvent).submitter?.getAttribute("value") === "register" ? "/api/account" : "/api/session", { method: "POST", body: JSON.stringify({ email: element<HTMLInputElement>("email").value, password: element<HTMLInputElement>("password").value }) });
    element<HTMLInputElement>("password").value = ""; await loadSession(); announce("Signed in."); element<HTMLInputElement>("title").focus();
  });
});
element<HTMLFormElement>("note-form").addEventListener("submit", event => {
  event.preventDefault(); const input = element<HTMLInputElement>("title"); const title = input.value.trim(); if (!title) return;
  if (pendingNote?.title !== title) pendingNote = { id: crypto.randomUUID(), title };
  const operation = pendingNote;
  void action((event.currentTarget as HTMLFormElement).querySelector("button")!, async () => {
    await api("/api/notes", { method: "POST", body: JSON.stringify(operation) }); pendingNote = undefined; input.value = ""; await refresh(); announce("Note added."); input.focus();
  });
});
element<HTMLButtonElement>("sign-out").addEventListener("click", event => { void action(event.currentTarget as HTMLButtonElement, async () => { await api("/api/session", { method: "DELETE" }); signedIn(false); announce("Signed out."); }); });

async function loadSession() {
  const session = await api("/api/session"); signedIn(true);
  element("sign-out").hidden = Boolean(session.preview);
  element("account-controls").hidden = Boolean(session.preview || session.development);
  const verified = session.user?.emailVerified !== false;
  element("verification").hidden = verified; element("note-form").hidden = !verified;
  if (verified) await refresh();
  announce(session.preview ? "Private preview: synthetic data, cleared on restart." : session.development ? "Local development: no external identity service is used." : verified ? "" : "Check your email to verify your account, then sign in again.");
}
element<HTMLButtonElement>("reset-password").addEventListener("click", event => { void action(event.currentTarget as HTMLButtonElement, async () => {
  await api("/api/account/reset", { method: "POST", body: JSON.stringify({ email: element<HTMLInputElement>("email").value }) }); announce("If the account exists, a recovery email is on its way.");
}); });
element<HTMLButtonElement>("send-verification").addEventListener("click", event => { void action(event.currentTarget as HTMLButtonElement, async () => { await api("/api/account/verify", { method: "POST" }); announce("Check your email to verify your account."); }); });
for (const [id, path, method] of [["sign-out-all", "/api/session/revoke", "POST"], ["delete-account", "/api/account", "DELETE"]] as const) {
  element<HTMLButtonElement>(id).addEventListener("click", event => {
    if (id === "delete-account" && !confirm("Delete your account and all your notes?")) return;
    void action(event.currentTarget as HTMLButtonElement, async () => { await api(path, { method }); signedIn(false); announce(id === "delete-account" ? "Account and notes deleted." : "Signed out on all devices."); });
  });
}
const link = new URL(location.href); const code = link.searchParams.get("oobCode"); const mode = link.searchParams.get("mode");
if (code && ["verifyEmail", "resetPassword"].includes(mode ?? "")) {
  history.replaceState(null, "", location.pathname);
  element("sign-in").hidden = true; element("account-action").hidden = false;
  element("new-password-label").hidden = mode !== "resetPassword";
  element<HTMLInputElement>("new-password").required = mode === "resetPassword";
  element<HTMLFormElement>("account-form").addEventListener("submit", event => { event.preventDefault(); void action((event.currentTarget as HTMLFormElement).querySelector("button")!, async () => {
    await api("/api/account/confirm", { method: "POST", body: JSON.stringify({ code, ...(mode === "resetPassword" ? { password: element<HTMLInputElement>("new-password").value } : {}) }) });
    await api("/api/session", { method: "DELETE" }); element("account-action").hidden = true; signedIn(false); announce("Account updated. Sign in to continue.");
  }); });
} else {
  try { await loadSession(); } catch { signedIn(false); announce(location.hostname === "127.0.0.1" || location.hostname === "localhost" ? "Local development: use any email and password." : "Sign in to continue."); }
}
