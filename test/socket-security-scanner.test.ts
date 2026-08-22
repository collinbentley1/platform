import { describe, expect, test } from "bun:test";
import { createSocketScanner } from "../tools/socket-security-scanner";

describe("platform Socket security scanner", () => {
  test("scans the maximum reviewed package set only through credentialless public requests", async () => {
    const requests: Array<{
      body: BodyInit | null | undefined;
      headers: Headers;
      method: string | undefined;
      redirect: RequestRedirect | undefined;
      url: string;
    }> = [];
    const fetcher: typeof fetch = async (input, init) => {
      const url = String(input);
      requests.push({
        body: init?.body,
        headers: new Headers(init?.headers),
        method: init?.method,
        redirect: init?.redirect,
        url,
      });
      const purl = decodeURIComponent(url.split("/").at(-1) ?? "");
      return new Response(publicBody(purl));
    };
    const packages = Array.from({ length: 128 }, (_, index) =>
      packageEntry(`pkg-${index}`, "1.0.0"));

    expect(await createSocketScanner({ fetcher }).scan({ packages })).toEqual([]);
    expect(requests).toHaveLength(128);
    expect(new Set(requests.map(({ url }) => url)).size).toBe(128);
    for (const request of requests) {
      expect(request.url).toStartWith("https://firewall-api.socket.dev/purl/");
      expect(request.body).toBeUndefined();
      expect(request.method).toBeUndefined();
      expect(request.redirect).toBe("error");
      expect(request.headers.get("accept")).toBe("application/x-ndjson");
      expect(request.headers.has("authorization")).toBe(false);
    }
  });

  test("rejects an attacker-inflated package set before any request", async () => {
    let requests = 0;
    const packages = Array.from({ length: 129 }, (_, index) =>
      packageEntry(`pkg-${index}`, "1.0.0"));
    const scan = createSocketScanner({
      fetcher: async () => {
        requests += 1;
        return new Response();
      },
    }).scan({ packages });

    await expect(scan).rejects.toThrow(
      "refusing to scan 129 packages; the reviewed limit is 128",
    );
    expect(requests).toBe(0);
  });

  test("fails closed on HTTP errors, omissions, and oversized public responses", async () => {
    await expect(
      createSocketScanner({
        fetcher: async () => new Response("", {
          headers: { "Retry-After": "60" },
          status: 429,
        }),
      }).scan({ packages: [packageEntry("safe", "1.0.0")] }),
    ).rejects.toThrow("public package policy request received HTTP 429; retry after 60s");

    await expect(
      createSocketScanner({ fetcher: async () => new Response("") }).scan({
        packages: [packageEntry("safe", "1.0.0")],
      }),
    ).rejects.toThrow("omitted 1 requested artifact");

    await expect(
      createSocketScanner({
        fetcher: async () => new Response("{}", {
          headers: { "Content-Length": String(10 * 1024 * 1024 + 1) },
        }),
      }).scan({ packages: [packageEntry("safe", "1.0.0")] }),
    ).rejects.toThrow("public package policy request response exceeds the size limit");
  });

  test("keeps the timeout active while reading the public response body", async () => {
    let requests = 0;
    const fetcher: typeof fetch = async (_input, init) => {
      requests += 1;
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
      createSocketScanner({ fetcher, timeoutMs: 5 }).scan({
        packages: [packageEntry("safe", "1.0.0")],
      }),
    ).rejects.toThrow("public package policy request failed");
    expect(requests).toBe(1);
  });

  test("rejects malformed, duplicate, unresolved, foreign, and summary public rows", async () => {
    const purl = "pkg:npm/safe@1.0.0";
    const cases = [
      ["not-json", "invalid NDJSON"],
      [[artifact(purl), artifact(purl)].map(JSON.stringify).join("\n"), "unexpected artifact"],
      [JSON.stringify({ _type: "purlError", value: { error: "missing", inputPurl: purl } }), "could not resolve"],
      [JSON.stringify({ _type: "summary", value: {} }), "invalid summary"],
      [JSON.stringify(artifact("pkg:npm/foreign@1.0.0")), "unexpected artifact"],
      [JSON.stringify({ inputPurl: purl }), "invalid artifact"],
      [JSON.stringify({ _type: "foreign" }), "unknown row type"],
    ] as const;

    for (const [body, expected] of cases) {
      await expect(
        createSocketScanner({ fetcher: async () => new Response(body) }).scan({
          packages: [packageEntry("safe", "1.0.0")],
        }),
      ).rejects.toThrow(expected);
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
      await expect(
        createSocketScanner({
          fetcher: async () => new Response(
            publicBody("pkg:npm/unsafe@1.0.0", [alert]),
          ),
        }).scan({ packages: [packageEntry("unsafe", "1.0.0")] }),
      ).rejects.toThrow("invalid alert");
    }
  });

  test("maps public Socket policy errors to fatal Bun advisories", async () => {
    const advisories = await createSocketScanner({
      fetcher: async () => new Response(publicBody("pkg:npm/unsafe@1.0.0", [
        {
          action: "error",
          fix: { description: "Remove it" },
          props: { description: "Known malware" },
          type: "malware",
        },
      ])),
    }).scan({ packages: [packageEntry("unsafe", "1.0.0")] });

    expect(advisories).toHaveLength(1);
    expect(advisories[0]).toMatchObject({
      description: "Known malware\n\nFix: Remove it\n",
      level: "fatal",
      package: "pkg:npm/unsafe@1.0.0",
    });
  });

  test("bounds public alert output and neutralizes workflow-command lines", async () => {
    const advisories = await createSocketScanner({
      fetcher: async () => new Response(publicBody("pkg:npm/unsafe@1.0.0", [
        {
          action: "error",
          props: {
            description:
              "Known malware\n  ::warning::forged runner command\ntext ##[add-mask]forged mask",
          },
          type: "malware",
        },
      ])),
    }).scan({ packages: [packageEntry("unsafe", "1.0.0")] });
    expect(advisories[0]?.description).toContain("  : :warning: :forged runner command");
    expect(advisories[0]?.description).toContain("text # #[add-mask]forged mask");
    expect(advisories[0]?.description).not.toContain("::");
    expect(advisories[0]?.description).not.toContain("##[");

    await expect(
      createSocketScanner({
        fetcher: async () => new Response(publicBody(
          "pkg:npm/unsafe@1.0.0",
          Array.from({ length: 257 }, () => ({ action: "warn", type: "unmaintained" })),
        )),
      }).scan({ packages: [packageEntry("unsafe", "1.0.0")] }),
    ).rejects.toThrow("returned too many alerts");
  });

  test("public mode never sends authorization and rejects invalid timeout configuration", async () => {
    const headers: Headers[] = [];
    const logs: string[] = [];
    const fetcher: typeof fetch = async (input, init) => {
      headers.push(new Headers(init?.headers));
      const purl = decodeURIComponent(String(input).split("/").at(-1) ?? "");
      return new Response(publicBody(purl));
    };

    expect(
      await createSocketScanner({ fetcher, logger: (message) => logs.push(message) }).scan({
        packages: [packageEntry("safe", "1.0.0")],
      }),
    ).toEqual([]);
    expect(headers.every((value) => !value.has("authorization"))).toBe(true);
    expect(logs).toEqual(["Socket Security Scanner free mode."]);
    expect(() => createSocketScanner({ timeoutMs: 0 })).toThrow("invalid request timeout");
  });
});

function publicBody(inputPurl: string, alerts: readonly unknown[] = []): string {
  return JSON.stringify(artifact(inputPurl, alerts));
}

function artifact(inputPurl: string, alerts: readonly unknown[] = []): object {
  return { alerts, inputPurl };
}

function packageEntry(name: string, version: string): Bun.Security.Package {
  return {
    name,
    requestedRange: version,
    tarball: `https://registry.npmjs.org/${name}/-/${name}-${version}.tgz`,
    version,
  };
}
