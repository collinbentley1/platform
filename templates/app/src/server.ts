const port = Number(Bun.env.PORT ?? 8080);

Bun.serve({
  port,
  fetch(request) {
    const url = new URL(request.url);

    if (url.pathname === "/livez") {
      const deployment = Bun.env.PLATFORM_DEPLOY_NONCE;
      return Response.json(deployment ? { ok: true, deployment } : { ok: true });
    }

    return new Response("__APP_NAME__", {
      headers: {
        "content-type": "text/plain; charset=utf-8",
      },
    });
  },
});
