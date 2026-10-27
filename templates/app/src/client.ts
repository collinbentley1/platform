type Note = { id: string; title: string; createdAt: string };
const element = <T extends HTMLElement>(id: string) => document.getElementById(id) as T;
const status = element<HTMLParagraphElement>("status");
let pendingNote: { id: string; title: string } | undefined;
function announce(message: string, error = false) { status.textContent = message; status.dataset.error = String(error); }
async function api(path: string, init: RequestInit = {}) {
  const response = await fetch(path, { credentials: "same-origin", ...init, headers: { "Content-Type": "application/json", ...Object.fromEntries(new Headers(init.headers)) }, signal: AbortSignal.timeout(15_000) });
  const body = await response.json() as { error?: string; notes?: Note[]; development?: boolean; preview?: boolean };
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
    await api("/api/session", { method: "POST", body: JSON.stringify({ email: element<HTMLInputElement>("email").value, password: element<HTMLInputElement>("password").value }) });
    element<HTMLInputElement>("password").value = ""; signedIn(true); await refresh(); announce("Signed in."); element<HTMLInputElement>("title").focus();
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
try { const session = await api("/api/session"); signedIn(true); await refresh(); element("sign-out").hidden = Boolean(session.preview); announce(session.preview ? "Private preview: synthetic data, cleared on restart." : session.development ? "Local development: no external identity service is used." : ""); }
catch { signedIn(false); announce(location.hostname === "127.0.0.1" || location.hostname === "localhost" ? "Local development: use any email and password." : "Sign in to continue."); }
