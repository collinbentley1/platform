import { describe, expect, test } from "bun:test";
import { createSocketScanner } from "../tools/socket-security-scanner";

describe("platform Socket security scanner", () => {
  test("uses one fail-closed organization request for the maximum reviewed package count", async () => {
    const requests: Array<{
      body?: string;
      headers: Headers;
      method?: string;
      redirect?: RequestRedirect;
      url: string;
    }> = [];
    const fetcher: typeof fetch = async (input, init) => {
      const url = String(input);
      requests.push({
        url,
        headers: new Headers(init?.headers),
        body: String(init?.body ?? ""),
        method: init?.method,
        redirect: init?.redirect,
      });
      if (url.endsWith("/quota")) {
        return Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null });
      }
      const body = JSON.parse(String(init?.body)) as { components: Array<{ purl: string }> };
      return new Response(authenticatedBody(body.components.map(({ purl }) => purl)));
    };
    const packages = Array.from({ length: 128 }, (_, index) => packageEntry(`pkg-${index}`, "1.0.0"));

    expect(await createSocketScanner({ fetcher, token: "synthetic-token" }).scan({ packages })).toEqual([]);
    expect(requests).toHaveLength(2);
    expect(requests[0]?.url).toBe("https://api.socket.dev/v0/quota");
    expect(requests[1]?.url).toBe(
      "https://api.socket.dev/v0/orgs/collinbentley1/purl?alerts=true&actions=error%2Cwarn&poll=true&purlErrors=true&summary=true&timeoutSec=25",
    );
    expect(JSON.parse(requests[1]?.body ?? "{}").components).toHaveLength(128);
    expect(requests[1]?.method).toBe("POST");
    expect(requests.every(({ redirect }) => redirect === "error")).toBe(true);
    expect(requests.every(({ headers }) => headers.get("authorization") === "Bearer synthetic-token")).toBe(true);
  });

  test("rejects an attacker-inflated package set before any request", async () => {
    let requests = 0;
    const packages = Array.from({ length: 129 }, (_, index) => packageEntry(`pkg-${index}`, "1.0.0"));
    const scan = createSocketScanner({
      fetcher: async () => {
        requests += 1;
        return new Response();
      },
      token: "synthetic-token",
    }).scan({ packages });

    await expect(scan).rejects.toThrow("refusing to scan 129 packages; the reviewed limit is 128");
    expect(requests).toBe(0);
  });

  test("fails before the batch request when quota is insufficient", async () => {
    const urls: string[] = [];
    const fetcher: typeof fetch = async (input) => {
      urls.push(String(input));
      return Response.json({ quota: 99, maxQuota: 500, nextWindowRefresh: "2026-08-22T00:00:00Z" });
    };
    const scan = createSocketScanner({ fetcher, token: "synthetic-token" }).scan({
      packages: [packageEntry("safe", "1.0.0")],
    });

    await expect(scan).rejects.toThrow("requires 100 units but only 99 remain");
    expect(urls).toEqual(["https://api.socket.dev/v0/quota"]);
  });

  test("fails closed on an incomplete or inconsistent quota response", async () => {
    for (const quota of [
      { quota: 500, maxQuota: 500 },
      { quota: 501, maxQuota: 500, nextWindowRefresh: null },
      { quota: 500, maxQuota: 500, nextWindowRefresh: "not-a-timestamp" },
    ]) {
      let requests = 0;
      await expect(
        createSocketScanner({
          fetcher: async () => {
            requests += 1;
            return Response.json(quota);
          },
          token: "synthetic-token",
        }).scan({ packages: [packageEntry("safe", "1.0.0")] }),
      ).rejects.toThrow("quota preflight returned an invalid response");
      expect(requests).toBe(1);
    }
  });

  test("fails closed on HTTP errors and incomplete responses", async () => {
    const quota = Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null });
    let request = 0;
    const httpFailure: typeof fetch = async () => (request++ === 0 ? quota.clone() : new Response("", { status: 429 }));
    await expect(
      createSocketScanner({ fetcher: httpFailure, token: "synthetic-token" }).scan({
        packages: [packageEntry("safe", "1.0.0")],
      }),
    ).rejects.toThrow("received HTTP 429");

    request = 0;
    const incomplete: typeof fetch = async () =>
      request++ === 0 ? quota.clone() : new Response("", { status: 200 });
    await expect(
      createSocketScanner({ fetcher: incomplete, token: "synthetic-token" }).scan({
        packages: [packageEntry("safe", "1.0.0")],
      }),
    ).rejects.toThrow("omitted 1 requested artifact");
  });

  test("keeps the timeout active while reading the response body", async () => {
    let request = 0;
    const fetcher: typeof fetch = async (_input, init) => {
      if (request++ === 0) {
        return Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null });
      }
      return new Response(
        new ReadableStream({
          start(controller) {
            init?.signal?.addEventListener(
              "abort",
              () => controller.error(new DOMException("aborted", "AbortError")),
              { once: true },
            );
          },
        }),
      );
    };

    await expect(
      createSocketScanner({ fetcher, timeoutMs: 5, token: "synthetic-token" }).scan({
        packages: [packageEntry("safe", "1.0.0")],
      }),
    ).rejects.toThrow("authenticated package policy request failed");
    expect(request).toBe(2);
  });

  test("rejects malformed, duplicate, unresolved, and incomplete authenticated streams", async () => {
    const purl = "pkg:npm/safe@1.0.0";
    const cases = [
      ["invalid NDJSON", "not-json", "invalid NDJSON"],
      [
        "duplicate artifact",
        [artifact(purl), artifact(purl), summary(1)].map(JSON.stringify).join("\n"),
        "unexpected artifact",
      ],
      [
        "PURL error",
        [
          JSON.stringify({ _type: "purlError", value: { error: "missing", inputPurl: purl } }),
          JSON.stringify(summary(1)),
        ].join("\n"),
        "could not resolve",
      ],
      ["missing summary", JSON.stringify(artifact(purl)), "omitted its completion summary"],
      [
        "inconsistent summary",
        [JSON.stringify(artifact(purl)), JSON.stringify(summary(2))].join("\n"),
        "invalid summary",
      ],
    ] as const;

    for (const [_label, body, expected] of cases) {
      let request = 0;
      const fetcher: typeof fetch = async () =>
        request++ === 0
          ? Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null })
          : new Response(body);
      await expect(
        createSocketScanner({ fetcher, token: "synthetic-token" }).scan({
          packages: [packageEntry("safe", "1.0.0")],
        }),
      ).rejects.toThrow(expected);
      expect(request).toBe(2);
    }
  });

  test("rejects unknown actions and fail-open synthetic alerts", async () => {
    for (const alert of [
      { action: "ignore", type: "malware", props: {} },
      { action: "error", type: "pendingScan", props: {} },
      { action: "warn", type: "notFound", props: {} },
      { action: "error", type: "##[add-mask]", props: {} },
      { action: "warn", type: "::warning::", props: {} },
    ]) {
      let request = 0;
      const fetcher: typeof fetch = async () => {
        if (request++ === 0) {
          return Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null });
        }
        return new Response(
          authenticatedBody(["pkg:npm/unsafe@1.0.0"], { "pkg:npm/unsafe@1.0.0": [alert] }),
        );
      };
      await expect(
        createSocketScanner({ fetcher, token: "synthetic-token" }).scan({
          packages: [packageEntry("unsafe", "1.0.0")],
        }),
      ).rejects.toThrow("invalid alert");
    }
  });

  test("maps Socket policy errors to fatal Bun advisories", async () => {
    let request = 0;
    const fetcher: typeof fetch = async (_input, init) => {
      if (request++ === 0) {
        return Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null });
      }
      const body = JSON.parse(String(init?.body)) as { components: Array<{ purl: string }> };
      return new Response(
        authenticatedBody([body.components[0]!.purl], {
          [body.components[0]!.purl]: [
            {
              action: "error",
              type: "malware",
              props: { description: "Known malware" },
              fix: { description: "Remove it" },
            },
          ],
        }),
      );
    };

    const advisories = await createSocketScanner({ fetcher, token: "synthetic-token" }).scan({
      packages: [packageEntry("unsafe", "1.0.0")],
    });
    expect(advisories).toHaveLength(1);
    expect(advisories[0]).toMatchObject({
      level: "fatal",
      package: "pkg:npm/unsafe@1.0.0",
      description: "Known malware\n\nFix: Remove it\n",
    });
  });

  test("bounds alert output and neutralizes workflow-command lines", async () => {
    let request = 0;
    const fetcher: typeof fetch = async () => {
      if (request++ === 0) {
        return Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null });
      }
      return new Response(
        authenticatedBody(["pkg:npm/unsafe@1.0.0"], {
          "pkg:npm/unsafe@1.0.0": [
            {
              action: "error",
              type: "malware",
              props: {
                description:
                  "Known malware\n  ::warning::forged runner command\ntext ##[add-mask]forged mask",
              },
            },
          ],
        }),
      );
    };
    const advisories = await createSocketScanner({ fetcher, token: "synthetic-token" }).scan({
      packages: [packageEntry("unsafe", "1.0.0")],
    });
    expect(advisories[0]?.description).toContain("  : :warning: :forged runner command");
    expect(advisories[0]?.description).toContain("text # #[add-mask]forged mask");
    expect(advisories[0]?.description).not.toContain("::");
    expect(advisories[0]?.description).not.toContain("##[");

    request = 0;
    const tooMany: typeof fetch = async () => {
      if (request++ === 0) {
        return Response.json({ quota: 500, maxQuota: 500, nextWindowRefresh: null });
      }
      return new Response(
        authenticatedBody(["pkg:npm/unsafe@1.0.0"], {
          "pkg:npm/unsafe@1.0.0": Array.from({ length: 257 }, () => ({
            action: "warn",
            type: "unmaintained",
          })),
        }),
      );
    };
    await expect(
      createSocketScanner({ fetcher: tooMany, token: "synthetic-token" }).scan({
        packages: [packageEntry("unsafe", "1.0.0")],
      }),
    ).rejects.toThrow("returned too many alerts");
  });

  test("public mode never sends an Authorization header", async () => {
    const headers: Headers[] = [];
    const logs: string[] = [];
    const fetcher: typeof fetch = async (input, init) => {
      headers.push(new Headers(init?.headers));
      const purl = decodeURIComponent(String(input).split("/").at(-1) ?? "");
      return new Response(JSON.stringify({ inputPurl: purl, alerts: [] }));
    };

    expect(
      await createSocketScanner({ fetcher, logger: (message) => logs.push(message), token: null }).scan({
        packages: [packageEntry("safe", "1.0.0")],
      }),
    ).toEqual([]);
    expect(headers.every((value) => !value.has("authorization"))).toBe(true);
    expect(logs).toEqual([
      "Socket Security Scanner free mode. Set SOCKET_API_TOKEN to use the organization policy.",
    ]);
  });

  test("rejects a blank configured token instead of silently falling back to free mode", async () => {
    let requests = 0;
    await expect(
      createSocketScanner({
        fetcher: async () => {
          requests += 1;
          return new Response();
        },
        token: "   ",
      }).scan({ packages: [packageEntry("safe", "1.0.0")] }),
    ).rejects.toThrow("SOCKET_API_TOKEN is invalid");
    expect(requests).toBe(0);
  });
});

function authenticatedBody(
  purls: readonly string[],
  alerts: Readonly<Record<string, readonly unknown[]>> = {},
): string {
  return [
    ...purls.map((purl) => JSON.stringify(artifact(purl, alerts[purl] ?? []))),
    JSON.stringify(summary(purls.length)),
  ].join("\n");
}

function artifact(inputPurl: string, alerts: readonly unknown[] = []): object {
  return { inputPurl, alerts };
}

function summary(count: number): object {
  return {
    _type: "summary",
    value: {
      purl_input: count,
      resolved: count,
      errors: {
        purl_malformed: 0,
        purl_ecosystem_not_enabled: 0,
        package_not_found: 0,
      },
    },
  };
}

function packageEntry(name: string, version: string): Bun.Security.Package {
  return {
    name,
    version,
    requestedRange: version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
  };
}
