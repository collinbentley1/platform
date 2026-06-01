const port = Number(Bun.env.PORT ?? 8080);

Bun.serve({
  port,
  fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/healthz") {
      return Response.json({ ok: true });
    }

    return new Response("__APP_NAME__", {
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    });
  },
});
