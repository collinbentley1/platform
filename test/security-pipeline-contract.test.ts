import { afterEach, describe, expect, test } from "bun:test";
import { createHash } from "node:crypto";
import { chmod, cp, mkdir, mkdtemp, readFile, rm, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";

const repoRoot = resolve(import.meta.dir, "..");
const helper = join(repoRoot, "tools/ci/container-artifact-contract.sh");
const fixture = join(
  repoRoot,
  "test/fixtures/buildkit-v0.32.2-application-container.tar.b64",
);
const exactRuntimeManifestFixture = join(
  repoRoot,
  "test/fixtures/dhi-bun-runtime-1.3.14-linux-amd64.manifest.json.b64",
);
const exactRuntimeConfigFixture = join(
  repoRoot,
  "test/fixtures/dhi-bun-runtime-1.3.14-linux-amd64.config.json.b64",
);
const headSha = "0123456789abcdef0123456789abcdef01234567";
const platformWorkflowSha = "3".repeat(40);
const dhiParityId = "1a4cho1elzg84pavos8mbanvvpmkieiht7kyhpjdofzpivf3k8";
const ovenChild = "8aac45197595035f697ea6b11cd73ce2401d82503fcb2540b5fac606973b242b";
const devChild = "58a392f5dec3be5cb20a2495baca84ac785f237a2d2904c5b9cad7ba11f3e475";
const runtimeChild = "0f9e5f506d653e0f87e44bb5c24fece19f9fb7253016f6e49d7a4783026f876d";
const temporaryRoots: string[] = [];

type JsonObject = Record<string, any>;
type ApplicationFixture = {
  baseRoot: string;
  builtConfigPath: string;
  imageRoot: string;
  indexDigest: string;
  runnableDigest: string;
  runtimeConfigPath: string;
};

afterEach(async () => {
  await Promise.all(
    temporaryRoots.splice(0).map((path) => rm(path, { recursive: true, force: true })),
  );
});

describe("protected container and preview lifecycle contracts", () => {
  test("the pinned BuildKit v0.32.2 tagged OCI fixture satisfies the full validator", async () => {
    const raw = await decodeBase64Fixture(fixture);
    expect(createHash("sha256").update(raw).digest("hex")).toBe(
      "e35a44cc35b225b862fb2f672e103efe886bcf8135cd23ff47fe62f227cf5265",
    );
    const original = await readOriginalBuildkitDocuments();
    const originalStatement = original.statement;
    expect(originalStatement._type).toBe("https://in-toto.io/Statement/v1");
    expect(originalStatement.predicateType).toBe("https://slsa.dev/provenance/v1");
    expect(originalStatement.subject).toEqual([{
      digest: { sha256: "b5ac4671e57b17e716674c0a68b65cdafd61cc75c61aadb52da375db2fca2e13" },
      name: `pkg:docker/platform-preview@${headSha}?platform=linux%2Famd64`,
    }]);
    expect(originalStatement.predicate.buildDefinition.buildType).toBe(
      "https://github.com/moby/buildkit/blob/master/docs/attestations/slsa-definitions.md",
    );
    expect(originalStatement.predicate.buildDefinition.resolvedDependencies).toEqual([
      material("bun-release", "ccdbe8a294dad8d9613bf7b55f686522e9e93a6122855c553559600262cdaf95"),
      material("dhi-bun-dev", "886a234efdf337d4c9dc046d0be2d5fb108b2421928897875709620109696798"),
      material("dhi-bun-runtime", "42cc819fdd3a3a8a7e70017bbacd83f88294e903117dbf53fd72e43a1ae5a992"),
    ]);
    expect(original.runnable.config).toEqual({
      digest: "sha256:8f60de4dc0a3265cc9e2a6b13d623b97beee61dc9c92960da61e8e416170e21b",
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: 3010,
    });
    expect(original.config.config).toEqual({
      ArgsEscaped: true,
      Cmd: ["/usr/local/bin/bun", "/app/dist/server.js"],
      Env: [
        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "NODE_ENV=production",
        "PORT=8080",
        "PUBLIC_DIR=/app/dist/public",
        "BUN_VERSION=1.4.0",
      ],
      ExposedPorts: { "8080/tcp": {} },
      Labels: {
        "org.opencontainers.image.base.digest": `sha256:${runtimeChild}`,
        "org.opencontainers.image.base.name": "dhi.io/bun:1-alpine",
        "org.opencontainers.image.revision": headSha,
        "org.opencontainers.image.source": "https://github.com/collinbentley1/example",
      },
      User: "65532:65532",
      WorkingDir: "/app",
    });
    expect(original.config.config.Entrypoint).toBeUndefined();

    const exactRuntimeManifest = await decodeBase64Fixture(exactRuntimeManifestFixture);
    const exactRuntimeConfig = await decodeBase64Fixture(exactRuntimeConfigFixture);
    expect(exactRuntimeManifest.byteLength).toBe(2598);
    expect(createHash("sha256").update(exactRuntimeManifest).digest("hex")).toBe(runtimeChild);
    expect(exactRuntimeConfig.byteLength).toBe(1941);
    expect(createHash("sha256").update(exactRuntimeConfig).digest("hex")).toBe(
      "124f28d97f9df90498fa9fc637fb7e78e30b5f427b804372a4e62c3db6cc5424",
    );
    expect(JSON.parse(exactRuntimeManifest.toString("utf8")).config).toEqual({
      digest: "sha256:124f28d97f9df90498fa9fc637fb7e78e30b5f427b804372a4e62c3db6cc5424",
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: 1941,
    });

    const application = await buildApplicationFixture();
    const result = await validateApplicationFixture(application);
    expect(result.exitCode, result.stderr).toBe(0);
    expect(result.stdout).toBe(`${application.indexDigest}\t${application.runnableDigest}\n`);
    expect(result.stdout).not.toContain("OK");

    const disabledRoot = await mkdtemp(join(tmpdir(), "platform-disabled-provenance-gate-"));
    temporaryRoots.push(disabledRoot);
    const disabledHelper = join(disabledRoot, "container-artifact-contract.sh");
    const helperBytes = await readFile(helper, "utf8");
    expect(helperBytes).toContain("readonly BUILDKIT_PROVENANCE_URI_POLICY_IMPLEMENTED=true");
    await writeFile(
      disabledHelper,
      helperBytes.replace(
        "readonly BUILDKIT_PROVENANCE_URI_POLICY_IMPLEMENTED=true",
        "readonly BUILDKIT_PROVENANCE_URI_POLICY_IMPLEMENTED=false",
      ),
    );
    await chmod(disabledHelper, 0o755);
    const disabled = await validateApplicationFixture(application, disabledHelper);
    expect(disabled.exitCode).not.toBe(0);
    expect(disabled.stderr).toContain(
      "Exact BuildKit v0.32.2 provenance material URIs are not yet frozen; application OCI validation is fail-closed.",
    );

    const configResult = await validateRuntimeConfig(
      application.builtConfigPath,
      application.runtimeConfigPath,
    );
    expect(configResult.exitCode, configResult.stderr).toBe(0);

    const lineageRoot = await mkdtemp(join(tmpdir(), "platform-runtime-lineage-"));
    temporaryRoots.push(lineageRoot);
    const runtimeManifestPath = join(lineageRoot, "runtime.json");
    const builtManifestPath = join(lineageRoot, "built.json");
    await writeFile(runtimeManifestPath, exactRuntimeManifest);
    const runtimeManifest = JSON.parse(exactRuntimeManifest.toString("utf8")) as JsonObject;
    await writeFile(
      builtManifestPath,
      JSON.stringify({
        layers: [
          ...runtimeManifest.layers,
          descriptorForBytes(Buffer.from("reviewed-app-layer\n")),
        ],
      }),
    );
    const manifestResult = await validateRuntimeManifest(
      builtManifestPath,
      runtimeManifestPath,
    );
    expect(manifestResult.exitCode, manifestResult.stderr).toBe(0);
  });

  test("the live image graph validator proves exact DHI lineage independently of parity labels", async () => {
    const application = await buildApplicationFixture();
    const loaded = await loadApplicationDocuments(application);
    loaded.documents.statement.subject[0].name =
      `pkg:docker/platform-production@${headSha}?platform=linux%2Famd64`;
    const graph = await persistApplicationGraph(
      application.imageRoot,
      loaded.documents,
      loaded.layerBlobs,
      new Set(["statementSubject"]),
    );
    application.indexDigest = graph.indexDigest;
    application.runnableDigest = graph.runnableDigest;
    const accepted = await validateLiveProductionFixture(application);
    expect(accepted.exitCode, accepted.stderr).toBe(0);

    const foreignParent = await validateLiveProductionFixture(application, "production", {
      index: `sha256:${"f".repeat(64)}`,
    });
    expect(foreignParent.exitCode).not.toBe(0);
    expect(foreignParent.stderr).toContain("Live production index differs from the Cloud Run image digest");

    const foreignChild = await validateLiveProductionFixture(application, "production", {
      runnable: `sha256:${"e".repeat(64)}`,
    });
    expect(foreignChild.exitCode).not.toBe(0);
    expect(foreignChild.stderr).toContain("Cloud Run runnable digest is not the child selected by the proven OCI index");

    const hostile = await loadApplicationDocuments(application);
    hostile.documents.statement.predicate.buildDefinition.resolvedDependencies[1].digest.sha256 =
      "f".repeat(64);
    const hostileGraph = await persistApplicationGraph(
      application.imageRoot,
      hostile.documents,
      hostile.layerBlobs,
      new Set(["statementSubject"]),
    );
    application.indexDigest = hostileGraph.indexDigest;
    application.runnableDigest = hostileGraph.runnableDigest;
    const rejected = await validateLiveProductionFixture(application);
    expect(rejected.exitCode).not.toBe(0);
    expect(rejected.stderr).toContain("OCI provenance statement drifted");

    const preview = await buildApplicationFixture();
    const previewDocuments = await loadApplicationDocuments(preview);
    const previewOnlyLayer = Buffer.from("preview application bytes deliberately differ from production\n");
    const previewOnlyDescriptor = descriptorForBytes(previewOnlyLayer);
    previewDocuments.documents.runnable.layers.push(previewOnlyDescriptor);
    previewDocuments.layerBlobs.set(previewOnlyDescriptor.digest, previewOnlyLayer);
    const previewGraph = await persistApplicationGraph(
      preview.imageRoot,
      previewDocuments.documents,
      previewDocuments.layerBlobs,
    );
    preview.indexDigest = previewGraph.indexDigest;
    preview.runnableDigest = previewGraph.runnableDigest;
    expect(preview.indexDigest).not.toBe(application.indexDigest);
    expect(preview.runnableDigest).not.toBe(application.runnableDigest);
    const unchangedCloudRunLabels = { "dhi-parity-id": dhiParityId };
    const acceptedPreview = await validateLiveProductionFixture(preview, "preview");
    expect(acceptedPreview.exitCode, acceptedPreview.stderr).toBe(0);
    expect(unchangedCloudRunLabels["dhi-parity-id"]).toBe(dhiParityId);

    const hostilePreview = await loadApplicationDocuments(preview);
    hostilePreview.documents.statement.predicate.buildDefinition.resolvedDependencies[1].digest.sha256 =
      "e".repeat(64);
    const hostilePreviewGraph = await persistApplicationGraph(
      preview.imageRoot,
      hostilePreview.documents,
      hostilePreview.layerBlobs,
      new Set(["statementSubject"]),
    );
    preview.indexDigest = hostilePreviewGraph.indexDigest;
    preview.runnableDigest = hostilePreviewGraph.runnableDigest;
    const rejectedPreview = await validateLiveProductionFixture(preview, "preview");
    expect(rejectedPreview.exitCode).not.toBe(0);
    expect(rejectedPreview.stderr).toContain("OCI provenance statement drifted");
    expect(unchangedCloudRunLabels["dhi-parity-id"]).toBe(dhiParityId);
  });

  test("application OCI validation rejects provenance and graph confusion", async () => {
    const hostile: ApplicationMutationCase[] = [
      statementMutation("missing dev material", "OCI provenance statement drifted", ({ statement }) => {
        statement.predicate.buildDefinition.resolvedDependencies.splice(1, 1);
      }),
      statementMutation("extra image material", "OCI provenance statement drifted", ({ statement }) => {
        statement.predicate.buildDefinition.resolvedDependencies.push(
          material("evil", "f".repeat(64)),
        );
      }),
      statementMutation("swapped dev material", "OCI provenance statement drifted", ({ statement }) => {
        statement.predicate.buildDefinition.resolvedDependencies[1].digest.sha256 = "e".repeat(64);
      }),
      statementMutation("foreign runnable subject", "OCI provenance statement drifted", ({ statement }) => {
        statement.subject[0].digest.sha256 = "d".repeat(64);
      }, new Set(["statementSubject"])),
      statementMutation("foreign runnable subject name", "OCI provenance statement drifted", ({ statement }) => {
        statement.subject[0].name = `pkg:docker/platform-evil@${headSha}?platform=linux%2Famd64`;
      }, new Set(["statementSubject"])),
      statementMutation("extra runnable subject", "OCI provenance statement drifted", ({ statement }) => {
        statement.subject.push(structuredClone(statement.subject[0]));
      }, new Set(["statementSubject"])),
      statementMutation("wrong predicate", "OCI provenance statement drifted", ({ statement }) => {
        statement.predicateType = "https://slsa.dev/provenance/v0.2";
      }),
      statementMutation("wrong storage form", "OCI provenance manifest schema drifted", ({ attestation }) => {
        attestation.artifactType = "application/vnd.in-toto+json";
      }),
      statementMutation("attestation bound to another runnable", "OCI provenance manifest schema drifted", ({ attestation }) => {
        attestation.subject.digest = `sha256:${"c".repeat(64)}`;
      }, new Set(["attestationSubject"])),
      statementMutation("runtime prefix descriptor mutation", "Final runtime layers do not exactly extend", ({ runtimeManifest }) => {
        runtimeManifest.layers[0].size += 1;
      }),
      statementMutation("runtime prefix descriptor reorder", "Final runtime layers do not exactly extend", ({ runtimeManifest }) => {
        [runtimeManifest.layers[0], runtimeManifest.layers[1]] =
          [runtimeManifest.layers[1], runtimeManifest.layers[0]];
      }),
      statementMutation("runnable layer size mutation", "Runnable OCI layer size drifted", ({ runnable }) => {
        runnable.layers[0].size += 1;
      }),
      statementMutation("runtime config user mutation", "Final runtime config does not exactly derive", ({ config }) => {
        config.config.User = "0";
      }),
      statementMutation("runtime command mutation", "Final runtime config does not exactly derive", ({ config }) => {
        config.config.Cmd = ["/bin/sh"];
      }),
      statementMutation("runtime diff-id prefix mutation", "Final runtime config does not exactly derive", ({ config }) => {
        config.rootfs.diff_ids[0] = `sha256:${"a".repeat(64)}`;
      }),
      statementMutation("runtime history prefix mutation", "Final runtime config does not exactly derive", ({ config }) => {
        config.history[0].created_by = "foreign base";
      }),
      outerMutation("foreign outer name", "BuildKit outer OCI wrapper schema drifted", (outer) => {
        outer.manifests[0].annotations["io.containerd.image.name"] = `docker.io/library/evil:${headSha}`;
      }),
      outerMutation("foreign outer ref", "BuildKit outer OCI wrapper schema drifted", (outer) => {
        outer.manifests[0].annotations["org.opencontainers.image.ref.name"] = "f".repeat(40);
      }),
      outerMutation("extra outer annotation", "BuildKit outer OCI wrapper schema drifted", (outer) => {
        outer.manifests[0].annotations.unreviewed = "true";
      }),
      outerMutation("wrong outer media type", "BuildKit outer OCI wrapper schema drifted", (outer) => {
        outer.manifests[0].mediaType = "application/vnd.oci.image.manifest.v1+json";
      }),
      outerMutation("wrong outer size", "BuildKit inner index size drifted", (outer) => {
        outer.manifests[0].size += 1;
      }),
      innerMutation("swapped inner descriptors", "BuildKit inner OCI index schema drifted", (inner) => {
        inner.manifests.reverse();
      }),
      innerMutation("foreign runnable platform", "BuildKit inner OCI index schema drifted", (inner) => {
        inner.manifests[0].platform.architecture = "arm64";
      }),
      innerMutation("foreign runnable media type", "BuildKit inner OCI index schema drifted", (inner) => {
        inner.manifests[0].mediaType = "application/vnd.docker.distribution.manifest.v2+json";
      }),
      innerMutation("wrong runnable size", "Runnable OCI manifest size drifted", (inner) => {
        inner.manifests[0].size += 1;
      }),
      innerMutation("missing inner descriptor", "BuildKit inner OCI index schema drifted", (inner) => {
        inner.manifests.pop();
      }),
      innerMutation("extra inner descriptor", "BuildKit inner OCI index schema drifted", (inner) => {
        inner.manifests.push(structuredClone(inner.manifests[0]));
      }),
      {
        expected: "Application OCI archive contains missing or unreachable blobs",
        label: "extra unreachable blob",
        mutate: async (application) => {
          const bytes = Buffer.from("unreachable\n");
          await writeFile(blobPath(application.imageRoot, createHash("sha256").update(bytes).digest("hex")), bytes);
          return application;
        },
      },
      {
        expected: "Application OCI blob directory contains a nested or non-regular entry",
        label: "nested blob directory",
        mutate: async (application) => {
          const nested = join(application.imageRoot, "blobs/sha256/nested");
          await mkdir(nested);
          await writeFile(join(nested, "hidden"), "unreachable\n");
          return application;
        },
      },
      {
        expected: "Expected a regular JSON file",
        label: "missing materialized empty config",
        mutate: async (application) => {
          await rm(blobPath(application.imageRoot, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"));
          return application;
        },
      },
      {
        expected: "JSON nesting or quoting exceeds the reviewed parser envelope",
        label: "pathologically deep JSON",
        mutate: async (application) => {
          await writeFile(
            join(application.imageRoot, "index.json"),
            `${"[".repeat(65)}0${"]".repeat(65)}`,
          );
          return application;
        },
      },
      {
        expected: "JSON file exceeds its byte cap",
        label: "oversized JSON",
        mutate: async (application) => {
          await writeFile(
            join(application.imageRoot, "index.json"),
            JSON.stringify({ padding: "x".repeat(1_048_576) }),
          );
          return application;
        },
      },
    ];

    for (const { expected, label, mutate } of hostile) {
      const application = await buildApplicationFixture();
      const baseline = await validateApplicationFixture(application);
      expect(baseline.exitCode, `${label} baseline failed: ${baseline.stderr}`).toBe(0);
      const hostileApplication = await mutate(application);
      const result = await validateApplicationFixture(hostileApplication);
      expect(result.exitCode, `${label} unexpectedly passed`).not.toBe(0);
      expect(result.stderr, `${label} rejected for the wrong reason`).toContain(expected);
    }
  }, 60_000);

  test("exact Oven children bypass DHI attestations while both DHI roles require them", async () => {
    for (const [role, expectedOutput] of [
      ["oven", ""],
      ["dhi_dev", `dhi_dev\tsha256:${runtimeChild}\n`],
      ["dhi_runtime", `dhi_runtime\tsha256:${runtimeChild}\n`],
    ] as const) {
      const result = await executeChildVerificationDispatch(role);
      expect(result.exitCode, `${role}: ${result.stderr}`).toBe(0);
      expect(result.stdout).toBe(expectedOutput);
    }

    const unsupported = await executeChildVerificationDispatch("foreign");
    expect(unsupported.exitCode).not.toBe(0);
    expect(unsupported.stderr).toContain("unsupported role");
    const unsupportedDiscovery = await executeChildVerificationDispatch("foreign", "discover");
    expect(unsupportedDiscovery.exitCode).not.toBe(0);
    expect(unsupportedDiscovery.stderr).toContain("unsupported role");

    const mismatch = await executeChildVerificationDispatch(
      "oven",
      `sha256:${"f".repeat(64)}`,
    );
    expect(mismatch.exitCode).not.toBe(0);
    expect(mismatch.stderr).toContain("Pinned linux/amd64 child digest mismatch for oven");
  });

  test("the Grype database manifest can only come from immutable platform policy bytes", async () => {
    const baseline = await executeGrypeManifestCheck(helper);
    expect(baseline.exitCode, baseline.stderr).toBe(0);

    for (const injected of [
      { DB_MANIFEST_JSON: "{}" },
      { GRYPE_DB_MANIFEST_JSON: "{}" },
    ]) {
      const result = await executeGrypeManifestCheck(helper, injected);
      expect(result.exitCode).not.toBe(0);
      expect(result.stderr).toContain("Refusing an injected Grype database manifest");
    }

    const symlinkRoot = await mkdtemp(join(tmpdir(), "platform-grype-manifest-symlink-"));
    temporaryRoots.push(symlinkRoot);
    const symlinkHelper = join(symlinkRoot, "container-artifact-contract.sh");
    await cp(helper, symlinkHelper);
    await symlink(join(repoRoot, "tools/ci/grype-db.json"), join(symlinkRoot, "grype-db.json"));
    const linked = await executeGrypeManifestCheck(symlinkHelper);
    expect(linked.exitCode).not.toBe(0);
    expect(linked.stderr).toContain("not a regular policy file");

    const modifiedRoot = await mkdtemp(join(tmpdir(), "platform-grype-manifest-modified-"));
    temporaryRoots.push(modifiedRoot);
    const modifiedHelper = join(modifiedRoot, "container-artifact-contract.sh");
    await cp(helper, modifiedHelper);
    await writeFile(join(modifiedRoot, "grype-db.json"), "{}\n");
    const modified = await executeGrypeManifestCheck(modifiedHelper);
    expect(modified.exitCode).not.toBe(0);
    expect(modified.stderr).toContain("SHA-256 verification failed");
  });

  test("exact immutable DHI runtime lineage rejects prefix and config substitutions", async () => {
    const root = await mkdtemp(join(tmpdir(), "platform-exact-runtime-lineage-"));
    temporaryRoots.push(root);
    const runtimeManifestBytes = await decodeBase64Fixture(exactRuntimeManifestFixture);
    const runtimeConfigBytes = await decodeBase64Fixture(exactRuntimeConfigFixture);
    const runtimeManifest = JSON.parse(runtimeManifestBytes.toString("utf8")) as JsonObject;
    const runtimeConfig = JSON.parse(runtimeConfigBytes.toString("utf8")) as JsonObject;
    const runtimeManifestPath = join(root, "runtime-manifest.json");
    const runtimeConfigPath = join(root, "runtime-config.json");
    await writeFile(runtimeManifestPath, runtimeManifestBytes);
    await writeFile(runtimeConfigPath, runtimeConfigBytes);
    const appLayer = descriptorForBytes(Buffer.from("exact-lineage-app-layer\n"));

    const manifestMutations: Array<[string, (layers: JsonObject[]) => void]> = [
      ["descriptor digest", (layers) => { layers[0].digest = `sha256:${"a".repeat(64)}`; }],
      ["descriptor size", (layers) => { layers[0].size += 1; }],
      ["descriptor order", (layers) => { [layers[0], layers[1]] = [layers[1], layers[0]]; }],
      ["missing prefix descriptor", (layers) => { layers.splice(2, 1); }],
      ["inserted pre-prefix descriptor", (layers) => { layers.unshift(structuredClone(appLayer)); }],
    ];
    for (const [label, mutate] of manifestMutations) {
      const baselinePath = join(root, `manifest-${label.replaceAll(" ", "-")}-baseline.json`);
      await writeFile(
        baselinePath,
        JSON.stringify({ layers: [...runtimeManifest.layers, appLayer] }),
      );
      const baseline = await validateRuntimeManifest(baselinePath, runtimeManifestPath);
      expect(baseline.exitCode, `${label} baseline failed: ${baseline.stderr}`).toBe(0);
      const layers = structuredClone([...runtimeManifest.layers, appLayer]);
      mutate(layers);
      const hostilePath = baselinePath.replace("baseline", "hostile");
      await writeFile(hostilePath, JSON.stringify({ layers }));
      const hostile = await validateRuntimeManifest(hostilePath, runtimeManifestPath);
      expect(hostile.exitCode, `${label} unexpectedly passed`).not.toBe(0);
      expect(hostile.stderr).toContain(
        "Final runtime layers do not exactly extend the reviewed DHI runtime descriptors",
      );
    }

    const baselineConfig = deriveApplicationConfig(runtimeConfig);
    baselineConfig.rootfs.diff_ids.push(`sha256:${"b".repeat(64)}`);
    baselineConfig.history.push({ created_by: "COPY app", comment: "buildkit.dockerfile.v0" });
    const configMutations: Array<[string, (config: JsonObject) => void]> = [
      ["user", (config) => { config.config.User = "0"; }],
      ["command", (config) => { config.config.Cmd = ["/bin/sh"]; }],
      ["Bun version", (config) => {
        config.config.Env = config.config.Env.map((value: string) =>
          value.startsWith("BUN_VERSION=") ? "BUN_VERSION=1.3.14" : value);
      }],
      ["base digest label", (config) => {
        config.config.Labels["org.opencontainers.image.base.digest"] = `sha256:${"c".repeat(64)}`;
      }],
      ["base name label", (config) => {
        config.config.Labels["org.opencontainers.image.base.name"] = "docker.io/library/bun:latest";
      }],
      ["diff-id prefix", (config) => { config.rootfs.diff_ids[0] = `sha256:${"d".repeat(64)}`; }],
      ["history prefix", (config) => { config.history[0].created_by = "foreign root"; }],
    ];
    for (const [label, mutate] of configMutations) {
      const baselinePath = join(root, `config-${label.replaceAll(" ", "-")}-baseline.json`);
      await writeFile(baselinePath, JSON.stringify(baselineConfig));
      const baseline = await validateRuntimeConfig(baselinePath, runtimeConfigPath);
      expect(baseline.exitCode, `${label} baseline failed: ${baseline.stderr}`).toBe(0);
      const hostileConfig = structuredClone(baselineConfig);
      mutate(hostileConfig);
      const hostilePath = baselinePath.replace("baseline", "hostile");
      await writeFile(hostilePath, JSON.stringify(hostileConfig));
      const hostile = await validateRuntimeConfig(hostilePath, runtimeConfigPath);
      expect(hostile.exitCode, `${label} unexpectedly passed`).not.toBe(0);
      expect(hostile.stderr).toContain(
        "Final runtime config does not exactly derive from the reviewed DHI runtime config",
      );
    }
  }, 30_000);

  test("tar extraction rejects aliases, traversal, links, devices, sparse entries, and oversize input", async () => {
    const baseline = await executeSafeExtract(createTar([
      { name: "layout/", type: "5" },
      { data: Buffer.from("1.0.0\n"), name: "layout/oci-layout", type: "0" },
    ]));
    expect(baseline.exitCode, baseline.stderr).toBe(0);
    expect(await readFile(join(baseline.destination, "layout/oci-layout"), "utf8")).toBe("1.0.0\n");

    const hostile: Array<[string, TarEntry[], string]> = [
      ["parent traversal", [{ data: Buffer.from("x"), name: "../escape", type: "0" }], "path traversal"],
      ["absolute path", [{ data: Buffer.from("x"), name: "/escape", type: "0" }], "path traversal"],
      ["duplicate path", [
        { data: Buffer.from("a"), name: "same", type: "0" },
        { data: Buffer.from("b"), name: "same", type: "0" },
      ], "duplicate paths"],
      ["dot alias duplicate", [
        { data: Buffer.from("a"), name: "same", type: "0" },
        { data: Buffer.from("b"), name: "./same", type: "0" },
      ], "duplicate paths"],
      ["symlink", [{ linkName: "target", name: "link", type: "2" }], "special file header"],
      ["hardlink", [{ linkName: "target", name: "hard", type: "1" }], "special file header"],
      ["fifo", [{ name: "fifo", type: "6" }], "special file header"],
      ["character device", [{ name: "device", type: "3" }], "special file header"],
      ["GNU sparse", [{ name: "sparse", type: "S" }], "special file header"],
      ["PAX extension", [{ data: Buffer.from("path=renamed\n"), name: "pax", type: "x" }], "special file header"],
      ["GNU long name", [{ data: Buffer.from("renamed\0"), name: "longname", type: "L" }], "special file header"],
      ["directory with data", [{ data: Buffer.from("hidden"), name: "directory/", type: "5" }], "directory carries unexpected data"],
    ];
    for (const [label, entries, expected] of hostile) {
      const result = await executeSafeExtract(createTar(entries));
      expect(result.exitCode, `${label} unexpectedly passed`).not.toBe(0);
      expect(result.stderr.toLowerCase(), `${label} rejected for the wrong reason`).toContain(expected);
    }

    const oversized = await executeSafeExtract(
      createTar([{ data: Buffer.alloc(1_100_000), name: "large", type: "0" }]),
      1_048_576,
    );
    expect(oversized.exitCode).not.toBe(0);
    expect(oversized.stderr).toContain("Artifact exceeds its byte cap");

    const trailingData = await executeSafeExtract(Buffer.concat([
      createTar([{ data: Buffer.from("reviewed\n"), name: "file", type: "0" }]),
      Buffer.concat([Buffer.from("hidden-after-end"), Buffer.alloc(512 - "hidden-after-end".length)]),
    ]));
    expect(trailingData.exitCode).not.toBe(0);
    expect(trailingData.stderr).toContain("Artifact hides data after the ustar end marker");
  }, 20_000);

  test("cleanup replays preserve state when the pull request lifecycle has advanced", async () => {
    const cleanup = Bun.YAML.parse(
      await readFile(join(repoRoot, ".github/workflows/cleanup-preview.yml"), "utf8"),
    ) as {
      jobs: { cleanup: { permissions: Record<string, string>; steps: Array<Record<string, any>> } };
    };
    expect(cleanup.jobs.cleanup.permissions["pull-requests"]).toBe("read");
    const lifecycle = cleanup.jobs.cleanup.steps.find(
      (step) => step.name === "Revalidate current pull request lifecycle before OIDC",
    );
    expect(lifecycle?.run).toBeString();
    for (const step of cleanup.jobs.cleanup.steps.slice(2)) {
      if (step.name === "Retire cleanup transaction credentials") {
        expect(step.if).toBe("always() && github.run_attempt == '1'");
      } else if (step.name === "Report fail-closed cleanup evidence failure") {
        expect(step.if).toBe("steps.fail-closed-seal.outputs.admitted == 'true'");
      } else {
        expect(step.if).toContain("steps.lifecycle.outputs.proceed == 'true'");
      }
    }

    const sameRepository = {
      id: 1255553151,
      full_name: "collinbentley1/cdbentley",
    };
    const matching = (overrides: JsonObject = {}) => ({
      base: { ref: "main" },
      draft: false,
      head: { repo: sameRepository, sha: headSha },
      state: "open",
      ...overrides,
    });
    const cases: Array<[string, string, JsonObject, boolean]> = [
      ["synchronize", headSha, matching(), true],
      ["synchronize", "b".repeat(40), matching(), false],
      ["closed", headSha, matching(), false],
      ["closed", headSha, matching({ state: "closed" }), true],
      ["converted_to_draft", headSha, matching({ draft: true }), true],
      ["converted_to_draft", headSha, matching({ draft: false }), false],
    ];
    for (const [action, eventHead, response, expected] of cases) {
      const result = await executeGhBackedStep(lifecycle?.run as string, response, {
        EVENT_ACTION: action,
        EVENT_HEAD_SHA: eventHead,
        EXPECTED_REPOSITORY: sameRepository.full_name,
        EXPECTED_REPOSITORY_ID: String(sameRepository.id),
        PR_NUMBER: "31",
      });
      expect(result.exitCode, result.stderr).toBe(0);
      expect(result.output).toContain(`proceed=${expected}`);
    }
  });

  test("preview reconciliation keeps only the current head and exact platform workflow SHA", async () => {
    const workflow = Bun.YAML.parse(
      await readFile(join(repoRoot, ".github/workflows/reconcile-previews.yml"), "utf8"),
    ) as { jobs: { reconcile: { if: string; steps: Array<Record<string, any>> } } };
    expect(workflow.jobs.reconcile.if).toBe(
      "always() && (github.event_name == 'push' || github.event_name == 'schedule' || github.event_name == 'workflow_dispatch') && github.ref == 'refs/heads/main'",
    );
    const reconcile = workflow.jobs.reconcile.steps.find(
      (step) => step.name === "Reconcile every route with one proven etag transaction",
    );
    expect(reconcile?.run).toBeString();
    expect(reconcile?.env?.EXPECTED_PLATFORM_WORKFLOW_SHA).toBe("${{ job.workflow_sha }}");
    expect(reconcile?.run).toContain('cloud-run-preview-controller.sh" reconcile');
    const controller = await readFile(
      join(repoRoot, "tools/ci/cloud-run-preview-controller.sh"),
      "utf8",
    );
    expect(controller).toContain('.metadata.labels["platform-workflow-sha"] == $workflow_sha');
    expect(controller).toContain('.metadata.labels["git-head-sha"] | test("^[0-9a-f]{40}$")');
    expect(controller).toContain('.state == "open" and .draft == false and .head.sha == $head');
    expect(controller).toContain("capture_proposed admitted true");
  });

  test("preview deployment stamps and verifies the exact reusable-workflow commit", async () => {
    const workflow = Bun.YAML.parse(
      await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8"),
    ) as { jobs: { deploy: { steps: Array<Record<string, any>> } } };
    const deploy = workflow.jobs.deploy.steps.find(
      (step) => step.name === "Deploy preview to Cloud Run",
    );
    expect(deploy?.env?.PLATFORM_WORKFLOW_SHA).toBe("${{ job.workflow_sha }}");
    expect(deploy?.run).toContain('[[ ! "$PLATFORM_WORKFLOW_SHA" =~ ^[0-9a-f]{40}$ ]]');
    expect(deploy?.run).toContain("platform-workflow-sha=${PLATFORM_WORKFLOW_SHA}");
    expect(deploy?.run).toContain('--arg workflow_sha "$PLATFORM_WORKFLOW_SHA"');
    expect(deploy?.run).toContain(
      '.metadata.labels["platform-workflow-sha"] == $workflow_sha',
    );
  });

  test("the WIF provider admits only GitHub-hosted jobs of the literal owner and repository IDs and maps one job-level authority composite", async () => {
    const source = await readFile(
      join(repoRoot, "terraform/modules/bootstrap/main.tf"),
      "utf8",
    );
    expect(source).toContain('github_owner_id     = "16823277"');
    expect(source).toContain('authority_delimiter = ":"');
    expect(source).toContain(
      'attribute_condition = "assertion.repository_owner_id == \'${local.github_owner_id}\' && assertion.repository_id == \'${var.github_repository_id}\' && assertion.runner_environment == \'github-hosted\'"',
    );
    for (const repositoryId of ["1255553151", "711292980", "1025243085", "280932482"]) {
      const condition = `assertion.repository_owner_id == '16823277' && assertion.repository_id == '${repositoryId}' && assertion.runner_environment == 'github-hosted'`;
      expect(condition.length).toBeLessThanOrEqual(4096);
      expect(condition.split(" && ")).toHaveLength(3);
      expect(condition).not.toMatch(/job_workflow|event_name|run_attempt|has\(|startsWith|\?/);
    }
    const mappingBlock = source.slice(
      source.indexOf("attribute_mapping = {"),
      source.indexOf("attribute_condition ="),
    );
    const mappings = [...mappingBlock.matchAll(/^\s*"([^"]+)"\s*=\s*"([^"]*)"\s*$/gm)].map((match) => [match[1], match[2]]);
    expect(mappings).toEqual([
      ["google.subject", "assertion.repository_owner_id + ':' + assertion.repository_id + ':' + assertion.run_id"],
      [
        "attribute.authority",
        "assertion.workflow_ref + '${local.authority_delimiter}' + assertion.job_workflow_ref + '${local.authority_delimiter}' + assertion.job_workflow_sha + '${local.authority_delimiter}' + assertion.environment + '${local.authority_delimiter}' + assertion.event_name",
      ],
    ]);
    for (const [, expression] of mappings) {
      expect(expression!.length).toBeLessThanOrEqual(2048);
      expect(expression).not.toMatch(/\?|has\(|run_attempt/);
    }
    expect(source).not.toContain("'denied'");
    expect(source).not.toContain("reconcile-previews.yml@");
  });

  test("a post-deploy API failure makes exact-revision invalidation mandatory", async () => {
    const workflow = Bun.YAML.parse(
      await readFile(join(repoRoot, ".github/workflows/deploy-preview.yml"), "utf8"),
    ) as {
      jobs: Record<string, Record<string, any>>;
    };
    const transaction = await readFile(
      join(repoRoot, "tools/ci/cloud-run-preview-traffic.sh"),
      "utf8",
    );
    expect(transaction).toContain('gh api "repos/${GITHUB_REPOSITORY}/pulls/${live_pr}"');
    expect(transaction).toContain("trap cleanup EXIT");
    expect(transaction).toContain("rollback_exact_traffic");
    expect(workflow.jobs.deploy.outputs["lifecycle-keep"]).toBe(
      "${{ steps.traffic-commit.outputs.admitted }}",
    );
    expect(workflow.jobs.invalidate.if).toBe(
      "always() && needs.deploy.outputs.deployed-revision != '' && (needs.deploy.outputs.lifecycle-keep != 'true' || needs.deploy.outputs.admission-open != 'success')",
    );
    const invalidate = workflow.jobs.invalidate.steps.find(
      (step: Record<string, any>) =>
        step.name === "Remove only the failed run's exact tag with one proven etag transaction",
    );
    const invalidateRun = invalidate.run as string;
    expect(invalidate.env.EXPECTED_TARGET_REVISION).toBe(
      "${{ needs.deploy.outputs.deployed-revision }}",
    );
    expect(invalidateRun).toContain('cloud-run-preview-controller.sh" remove');
    expect(transaction).toContain("rollback_exact_traffic");
    const controller = await readFile(
      join(repoRoot, "tools/ci/cloud-run-preview-controller.sh"),
      "utf8",
    );
    expect(controller).toContain(
      'if [ -n "$EXPECTED_TARGET_REVISION" ] && [ "$live_revision" != "$EXPECTED_TARGET_REVISION" ]',
    );
  });
});

type FixtureDocuments = {
  attestation: JsonObject;
  config: JsonObject;
  innerIndex: JsonObject;
  outerIndex: JsonObject;
  runnable: JsonObject;
  runtimeConfig: JsonObject;
  runtimeManifest: JsonObject;
  statement: JsonObject;
};

type GraphPreserve =
  | "attestationSubject"
  | "innerAttestationReference"
  | "statementSubject";

type ApplicationMutationCase = {
  expected: string;
  label: string;
  mutate: (application: ApplicationFixture) => Promise<ApplicationFixture>;
};

type TarEntry = {
  data?: Buffer;
  linkName?: string;
  name: string;
  size?: number;
  type: string;
};

async function buildApplicationFixture(): Promise<ApplicationFixture> {
  const root = await mkdtemp(join(tmpdir(), "platform-buildkit-fixture-"));
  temporaryRoots.push(root);
  const archive = join(root, "fixture.tar");
  await writeFile(archive, await decodeBase64Fixture(fixture));
  const imageRoot = join(root, "image");
  await mkdir(imageRoot);
  const extract = Bun.spawn(["tar", "-xf", archive, "-C", imageRoot], {
    stderr: "pipe",
    stdout: "ignore",
  });
  expect(await extract.exited, await new Response(extract.stderr).text()).toBe(0);

  const outerIndex = await readJson(join(imageRoot, "index.json"));
  const innerIndex = await readJson(blobPath(imageRoot, outerIndex.manifests[0].digest));
  const runnable = await readJson(blobPath(imageRoot, innerIndex.manifests[0].digest));
  const attestation = await readJson(blobPath(imageRoot, innerIndex.manifests[1].digest));
  const statement = await readJson(blobPath(imageRoot, attestation.layers[0].digest));

  statement.predicate.buildDefinition.resolvedDependencies = [
    material("bun-release", ovenChild),
    material("dhi-bun-dev", devChild),
    material("dhi-bun-runtime", runtimeChild),
  ];
  const baseRoot = join(root, "base");
  const baseLayout = join(baseRoot, "layouts/dhi_runtime");
  await mkdir(join(baseLayout, "blobs/sha256"), { recursive: true });
  const exactRuntimeConfigBytes = await decodeBase64Fixture(exactRuntimeConfigFixture);
  expect(createHash("sha256").update(exactRuntimeConfigBytes).digest("hex")).toBe(
    "124f28d97f9df90498fa9fc637fb7e78e30b5f427b804372a4e62c3db6cc5424",
  );
  expect(exactRuntimeConfigBytes.byteLength).toBe(1941);
  const runtimeConfig = JSON.parse(exactRuntimeConfigBytes.toString("utf8")) as JsonObject;
  const runtimeConfigPath = join(baseLayout, "blobs/sha256", "124f28d97f9df90498fa9fc637fb7e78e30b5f427b804372a4e62c3db6cc5424");
  await writeFile(runtimeConfigPath, exactRuntimeConfigBytes);

  const layerBlobs = new Map<string, Buffer>();
  const baseLayers = [];
  for (let index = 0; index < runtimeConfig.rootfs.diff_ids.length; index += 1) {
    const bytes = Buffer.from(`reviewed-runtime-layer-${index}\n`);
    const descriptor = descriptorForBytes(bytes, {
      "buildkit/rewritten-timestamp": "1780571786",
    });
    layerBlobs.set(descriptor.digest, bytes);
    baseLayers.push(descriptor);
  }
  const appLayerBytes = Buffer.from("reviewed-application-layer\n");
  const appLayer = descriptorForBytes(appLayerBytes);
  layerBlobs.set(appLayer.digest, appLayerBytes);

  const config = deriveApplicationConfig(runtimeConfig);
  config.rootfs.diff_ids.push(`sha256:${createHash("sha256").update("reviewed-application-rootfs\n").digest("hex")}`);
  config.history.push({
    comment: "buildkit.dockerfile.v0",
    created: "2026-08-22T21:05:57Z",
    created_by: "COPY /app/dist /app/dist # buildkit",
  });
  runnable.layers = [...baseLayers, appLayer];
  const runtimeManifest = {
    config: {
      digest: "sha256:124f28d97f9df90498fa9fc637fb7e78e30b5f427b804372a4e62c3db6cc5424",
      mediaType: "application/vnd.oci.image.config.v1+json",
      size: 1941,
    },
    layers: structuredClone(baseLayers),
  };

  const documents: FixtureDocuments = {
    attestation,
    config,
    innerIndex,
    outerIndex,
    runnable,
    runtimeConfig,
    runtimeManifest,
    statement,
  };
  const graph = await persistApplicationGraph(imageRoot, documents, layerBlobs);

  await writeFile(
    join(baseRoot, "manifest.json"),
    JSON.stringify({
      images: [
        { childDigest: `sha256:${ovenChild}`, role: "oven" },
        { childDigest: `sha256:${devChild}`, role: "dhi_dev" },
        { childDigest: `sha256:${runtimeChild}`, role: "dhi_runtime" },
      ],
    }),
  );
  await writeFile(
    join(baseLayout, "blobs/sha256", runtimeChild),
    JSON.stringify(runtimeManifest),
  );
  return {
    baseRoot,
    builtConfigPath: graph.builtConfigPath,
    imageRoot,
    indexDigest: graph.indexDigest,
    runnableDigest: graph.runnableDigest,
    runtimeConfigPath,
  };
}

function deriveApplicationConfig(runtimeConfig: JsonObject): JsonObject {
  const config = structuredClone(runtimeConfig);
  config.config.Env = [
    ...config.config.Env.filter(
      (value: string) => !/^(NODE_ENV|PORT|PUBLIC_DIR)=/.test(value),
    ).map((value: string) => value.startsWith("BUN_VERSION=") ? "BUN_VERSION=1.4.0" : value),
    "NODE_ENV=production",
    "PORT=8080",
    "PUBLIC_DIR=/app/dist/public",
  ];
  config.config.ExposedPorts = { ...(config.config.ExposedPorts ?? {}), "8080/tcp": {} };
  config.config.Labels = {
    ...(config.config.Labels ?? {}),
    "org.opencontainers.image.base.digest": `sha256:${runtimeChild}`,
    "org.opencontainers.image.base.name": "dhi.io/bun:1-alpine",
    "org.opencontainers.image.revision": headSha,
    "org.opencontainers.image.source": "https://github.com/collinbentley1/example",
  };
  config.config.User = "65532:65532";
  config.config.WorkingDir = "/app";
  config.config.ArgsEscaped = true;
  config.config.Cmd = ["/usr/local/bin/bun", "/app/dist/server.js"];
  delete config.config.Entrypoint;
  return config;
}

function descriptorForBytes(
  bytes: Buffer,
  annotations?: Record<string, string>,
): JsonObject {
  const descriptor: JsonObject = {
    digest: `sha256:${createHash("sha256").update(bytes).digest("hex")}`,
    mediaType: "application/vnd.oci.image.layer.v1.tar+zstd",
    size: bytes.byteLength,
  };
  if (annotations) descriptor.annotations = annotations;
  return descriptor;
}

async function persistApplicationGraph(
  imageRoot: string,
  documents: FixtureDocuments,
  layerBlobs: Map<string, Buffer>,
  preserve: ReadonlySet<GraphPreserve> = new Set(),
): Promise<{ builtConfigPath: string; indexDigest: string; runnableDigest: string }> {
  const blobRoot = join(imageRoot, "blobs/sha256");
  await rm(blobRoot, { recursive: true, force: true });
  await mkdir(blobRoot, { recursive: true });
  for (const [digest, bytes] of layerBlobs) {
    await writeFile(blobPath(imageRoot, digest), bytes);
  }
  await writeFile(
    blobPath(imageRoot, "44136fa355b3678a1146ad16f7e8649e94fb4fc21fe77e8310c060f61caaff8a"),
    "{}",
  );

  const configDescriptor = await writeJsonBlob(imageRoot, documents.config);
  documents.runnable.config = {
    digest: configDescriptor.digest,
    mediaType: "application/vnd.oci.image.config.v1+json",
    size: configDescriptor.size,
  };
  const runnableDescriptor = await writeJsonBlob(imageRoot, documents.runnable);
  documents.innerIndex.manifests[0] = {
    digest: runnableDescriptor.digest,
    mediaType: "application/vnd.oci.image.manifest.v1+json",
    platform: { architecture: "amd64", os: "linux" },
    size: runnableDescriptor.size,
  };
  if (!preserve.has("statementSubject")) {
    documents.statement.subject = [{
      digest: { sha256: stripDigest(runnableDescriptor.digest) },
      name: `pkg:docker/platform-preview@${headSha}?platform=linux%2Famd64`,
    }];
  }
  if (!preserve.has("attestationSubject")) {
    documents.attestation.subject = {
      digest: runnableDescriptor.digest,
      mediaType: "application/vnd.oci.image.manifest.v1+json",
      size: runnableDescriptor.size,
    };
  }
  if (!preserve.has("innerAttestationReference")) {
    documents.innerIndex.manifests[1].annotations["vnd.docker.reference.digest"] =
      runnableDescriptor.digest;
  }
  const statementDescriptor = await writeJsonBlob(imageRoot, documents.statement);
  documents.attestation.layers[0].digest = statementDescriptor.digest;
  documents.attestation.layers[0].size = statementDescriptor.size;
  const attestationDescriptor = await writeJsonBlob(imageRoot, documents.attestation);
  documents.innerIndex.manifests[1].digest = attestationDescriptor.digest;
  documents.innerIndex.manifests[1].size = attestationDescriptor.size;
  const innerDescriptor = await writeJsonBlob(imageRoot, documents.innerIndex);
  documents.outerIndex.manifests[0].digest = innerDescriptor.digest;
  documents.outerIndex.manifests[0].size = innerDescriptor.size;
  await writeFile(join(imageRoot, "index.json"), JSON.stringify(documents.outerIndex));
  return {
    builtConfigPath: blobPath(imageRoot, configDescriptor.digest),
    indexDigest: innerDescriptor.digest,
    runnableDigest: runnableDescriptor.digest,
  };
}

async function loadApplicationDocuments(
  application: ApplicationFixture,
): Promise<{ documents: FixtureDocuments; layerBlobs: Map<string, Buffer> }> {
  const outerIndex = await readJson(join(application.imageRoot, "index.json"));
  const innerIndex = await readJson(blobPath(application.imageRoot, outerIndex.manifests[0].digest));
  const runnable = await readJson(blobPath(application.imageRoot, innerIndex.manifests[0].digest));
  const config = await readJson(blobPath(application.imageRoot, runnable.config.digest));
  const attestation = await readJson(blobPath(application.imageRoot, innerIndex.manifests[1].digest));
  const statement = await readJson(blobPath(application.imageRoot, attestation.layers[0].digest));
  const runtimeManifest = await readJson(
    join(application.baseRoot, "layouts/dhi_runtime/blobs/sha256", runtimeChild),
  );
  const runtimeConfig = await readJson(application.runtimeConfigPath);
  const layerBlobs = new Map<string, Buffer>();
  for (const descriptor of runnable.layers) {
    layerBlobs.set(descriptor.digest, await readFile(blobPath(application.imageRoot, descriptor.digest)));
  }
  return {
    documents: {
      attestation,
      config,
      innerIndex,
      outerIndex,
      runnable,
      runtimeConfig,
      runtimeManifest,
      statement,
    },
    layerBlobs,
  };
}

async function rewriteApplicationGraph(
  application: ApplicationFixture,
  mutate: (documents: FixtureDocuments) => void | Promise<void>,
  preserve: ReadonlySet<GraphPreserve> = new Set(),
): Promise<ApplicationFixture> {
  const { documents, layerBlobs } = await loadApplicationDocuments(application);
  await mutate(documents);
  const graph = await persistApplicationGraph(
    application.imageRoot,
    documents,
    layerBlobs,
    preserve,
  );
  await writeFile(
    join(application.baseRoot, "layouts/dhi_runtime/blobs/sha256", runtimeChild),
    JSON.stringify(documents.runtimeManifest),
  );
  return {
    ...application,
    builtConfigPath: graph.builtConfigPath,
    indexDigest: graph.indexDigest,
    runnableDigest: graph.runnableDigest,
  };
}

async function rewriteInnerIndex(
  application: ApplicationFixture,
  mutate: (inner: JsonObject) => void,
): Promise<ApplicationFixture> {
  const outer = await readJson(join(application.imageRoot, "index.json"));
  const oldInnerPath = blobPath(application.imageRoot, outer.manifests[0].digest);
  const inner = await readJson(oldInnerPath);
  mutate(inner);
  const descriptor = await writeJsonBlob(application.imageRoot, inner);
  outer.manifests[0].digest = descriptor.digest;
  outer.manifests[0].size = descriptor.size;
  await writeFile(join(application.imageRoot, "index.json"), JSON.stringify(outer));
  return { ...application, indexDigest: descriptor.digest };
}

async function rewriteOuterIndex(
  application: ApplicationFixture,
  mutate: (outer: JsonObject) => void,
): Promise<ApplicationFixture> {
  const outer = await readJson(join(application.imageRoot, "index.json"));
  mutate(outer);
  await writeFile(join(application.imageRoot, "index.json"), JSON.stringify(outer));
  return application;
}

function statementMutation(
  label: string,
  expected: string,
  mutate: (documents: FixtureDocuments) => void | Promise<void>,
  preserve: ReadonlySet<GraphPreserve> = new Set(),
): ApplicationMutationCase {
  return {
    expected,
    label,
    mutate: (application) => rewriteApplicationGraph(application, mutate, preserve),
  };
}

function outerMutation(
  label: string,
  expected: string,
  mutate: (outer: JsonObject) => void,
): ApplicationMutationCase {
  return {
    expected,
    label,
    mutate: (application) => rewriteOuterIndex(application, mutate),
  };
}

function innerMutation(
  label: string,
  expected: string,
  mutate: (inner: JsonObject) => void,
): ApplicationMutationCase {
  return {
    expected,
    label,
    mutate: (application) => rewriteInnerIndex(application, mutate),
  };
}

async function readOriginalBuildkitDocuments(): Promise<{
  config: JsonObject;
  runnable: JsonObject;
  statement: JsonObject;
}> {
  const root = await mkdtemp(join(tmpdir(), "platform-original-buildkit-"));
  temporaryRoots.push(root);
  const archive = join(root, "application.tar");
  await writeFile(archive, await decodeBase64Fixture(fixture));
  const imageRoot = join(root, "image");
  await mkdir(imageRoot);
  const extraction = Bun.spawn(["tar", "-xf", archive, "-C", imageRoot], {
    stderr: "pipe",
    stdout: "ignore",
  });
  expect(
    await extraction.exited,
    await new Response(extraction.stderr).text(),
  ).toBe(0);
  const outer = await readJson(join(imageRoot, "index.json"));
  const inner = await readJson(blobPath(imageRoot, outer.manifests[0].digest));
  const runnable = await readJson(blobPath(imageRoot, inner.manifests[0].digest));
  const config = await readJson(blobPath(imageRoot, runnable.config.digest));
  const attestation = await readJson(blobPath(imageRoot, inner.manifests[1].digest));
  const statement = await readJson(blobPath(imageRoot, attestation.layers[0].digest));
  return { config, runnable, statement };
}

async function validateRuntimeConfig(
  builtConfigPath: string,
  runtimeConfigPath: string,
): Promise<{ exitCode: number; stderr: string }> {
  const child = Bun.spawn(["/bin/bash", helper, "test-runtime-config"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      CONTRACT_TEST_ONLY: "platform-buildkit-v0.32.2-fixture",
      RUNNER_TEMP: dirname(builtConfigPath),
      TEST_BUILT_CONFIG: builtConfigPath,
      TEST_HEAD_SHA: headSha,
      TEST_REPOSITORY: "collinbentley1/example",
      TEST_RUNTIME_CONFIG: runtimeConfigPath,
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stderr };
}

async function executeChildVerificationDispatch(
  role: string,
  expectedChild = `sha256:${runtimeChild}`,
): Promise<{ exitCode: number; stderr: string; stdout: string }> {
  const child = Bun.spawn(["/bin/bash", helper, "test-child-verification-dispatch"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      CONTRACT_TEST_ONLY: "platform-buildkit-v0.32.2-fixture",
      TEST_CHILD_DIGEST: `sha256:${runtimeChild}`,
      TEST_CHILD_ROLE: role,
      TEST_EXPECTED_CHILD_DIGEST: expectedChild,
    },
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stderr, stdout] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
    new Response(child.stdout).text(),
  ]);
  return { exitCode, stderr, stdout };
}

async function executeGrypeManifestCheck(
  helperPath: string,
  overrides: Record<string, string> = {},
): Promise<{ exitCode: number; stderr: string }> {
  const child = Bun.spawn(["/bin/bash", helperPath, "test-grype-db-manifest"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      CONTRACT_TEST_ONLY: "platform-buildkit-v0.32.2-fixture",
      DB_MANIFEST_JSON: "",
      GRYPE_DB_MANIFEST_JSON: "",
      ...overrides,
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stderr };
}

async function validateRuntimeManifest(
  builtManifestPath: string,
  runtimeManifestPath: string,
): Promise<{ exitCode: number; stderr: string }> {
  const child = Bun.spawn(["/bin/bash", helper, "test-runtime-manifest"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      CONTRACT_TEST_ONLY: "platform-buildkit-v0.32.2-fixture",
      RUNNER_TEMP: dirname(builtManifestPath),
      TEST_BUILT_MANIFEST: builtManifestPath,
      TEST_RUNTIME_MANIFEST: runtimeManifestPath,
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stderr };
}

function material(name: string, digest: string): JsonObject {
  return {
    digest: { sha256: digest },
    uri: `pkg:oci/platform.invalid/${name}?digest=sha256:${digest}&platform=linux%2Famd64`,
  };
}

async function decodeBase64Fixture(path: string): Promise<Buffer> {
  return Buffer.from((await readFile(path, "utf8")).replace(/\s+/g, ""), "base64");
}

function createTar(entries: TarEntry[]): Buffer {
  const parts: Buffer[] = [];
  for (const entry of entries) {
    const data = entry.data ?? Buffer.alloc(0);
    const declaredSize = entry.size ?? data.byteLength;
    const header = Buffer.alloc(512);
    writeTarString(header, 0, 100, entry.name);
    writeTarOctal(header, 100, 8, entry.type === "5" ? 0o755 : 0o644);
    writeTarOctal(header, 108, 8, 0);
    writeTarOctal(header, 116, 8, 0);
    writeTarOctal(header, 124, 12, declaredSize);
    writeTarOctal(header, 136, 12, 0);
    header.fill(0x20, 148, 156);
    header.write(entry.type, 156, 1, "ascii");
    writeTarString(header, 157, 100, entry.linkName ?? "");
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");
    const checksum = header.reduce((sum, byte) => sum + byte, 0);
    const checksumText = checksum.toString(8).padStart(6, "0");
    header.write(`${checksumText}\0 `, 148, 8, "ascii");
    parts.push(header);
    if (data.byteLength > 0) {
      parts.push(data);
      const padding = (512 - (data.byteLength % 512)) % 512;
      if (padding > 0) parts.push(Buffer.alloc(padding));
    }
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

function writeTarString(
  target: Buffer,
  offset: number,
  length: number,
  value: string,
): void {
  const bytes = Buffer.from(value, "utf8");
  if (bytes.byteLength > length) throw new Error(`tar value is too long: ${value}`);
  bytes.copy(target, offset);
}

function writeTarOctal(
  target: Buffer,
  offset: number,
  length: number,
  value: number,
): void {
  target.write(`${value.toString(8).padStart(length - 1, "0")}\0`, offset, length, "ascii");
}

async function executeSafeExtract(
  archiveBytes: Buffer,
  maxBytes = 2_000_000,
): Promise<{ destination: string; exitCode: number; stderr: string }> {
  const root = await mkdtemp(join(tmpdir(), "platform-safe-tar-"));
  temporaryRoots.push(root);
  const archive = join(root, "archive.tar");
  const destination = join(root, "destination");
  await writeFile(archive, archiveBytes);
  const child = Bun.spawn(["/bin/bash", helper, "test-safe-extract"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      CONTRACT_TEST_ONLY: "platform-buildkit-v0.32.2-fixture",
      RUNNER_TEMP: root,
      TEST_ARCHIVE: archive,
      TEST_DESTINATION: destination,
      TEST_MAX_BYTES: String(maxBytes),
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return { destination, exitCode, stderr };
}

async function writeJsonBlob(
  root: string,
  value: JsonObject,
): Promise<{ digest: string; size: number }> {
  const bytes = Buffer.from(JSON.stringify(value));
  const hex = createHash("sha256").update(bytes).digest("hex");
  const path = blobPath(root, hex);
  await mkdir(dirname(path), { recursive: true });
  await writeFile(path, bytes);
  return { digest: `sha256:${hex}`, size: bytes.byteLength };
}

async function readJson(path: string): Promise<JsonObject> {
  return JSON.parse(await readFile(path, "utf8")) as JsonObject;
}

function blobPath(root: string, digest: string): string {
  return join(root, "blobs/sha256", stripDigest(digest));
}

function stripDigest(digest: string): string {
  return digest.replace(/^sha256:/, "");
}

async function validateApplicationFixture(
  fixtureRoot: ApplicationFixture,
  helperPath = helper,
): Promise<{ exitCode: number; stderr: string; stdout: string }> {
  const child = Bun.spawn(["/bin/bash", helperPath, "test-application-oci"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      CONTRACT_TEST_ONLY: "platform-buildkit-v0.32.2-fixture",
      GITHUB_REPOSITORY: "collinbentley1/example",
      RUNNER_TEMP: dirname(fixtureRoot.imageRoot),
      TEST_BASE_ROOT: fixtureRoot.baseRoot,
      TEST_EXPECTED_INDEX_DIGEST: fixtureRoot.indexDigest,
      TEST_EXPECTED_RUNNABLE_DIGEST: fixtureRoot.runnableDigest,
      TEST_HEAD_SHA: headSha,
      TEST_IMAGE_ROOT: fixtureRoot.imageRoot,
      TEST_KIND: "preview",
    },
    stderr: "pipe",
    stdout: "pipe",
  });
  const [exitCode, stderr, stdout] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
    new Response(child.stdout).text(),
  ]);
  return { exitCode, stderr, stdout };
}

async function validateLiveProductionFixture(
  fixtureRoot: ApplicationFixture,
  kind: "preview" | "production" = "production",
  expected: { index?: string; runnable?: string } = {},
): Promise<{ exitCode: number; stderr: string }> {
  const child = Bun.spawn(["/bin/bash", helper, "test-live-production-graph"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      CONTRACT_TEST_ONLY: "platform-buildkit-v0.32.2-fixture",
      GITHUB_REPOSITORY: "collinbentley1/example",
      RUNNER_TEMP: dirname(fixtureRoot.imageRoot),
      TEST_BASE_ROOT: fixtureRoot.baseRoot,
      TEST_HEAD_SHA: headSha,
      TEST_IMAGE_ROOT: fixtureRoot.imageRoot,
      TEST_KIND: kind,
      TEST_EXPECTED_INDEX_DIGEST: expected.index ?? fixtureRoot.indexDigest,
      TEST_EXPECTED_RUNNABLE_DIGEST: expected.runnable ?? fixtureRoot.runnableDigest,
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return { exitCode, stderr };
}

async function executeGhBackedStep(
  run: string,
  response: JsonObject,
  env: Record<string, string>,
  fail = false,
): Promise<{ exitCode: number; output: string; stderr: string }> {
  const root = await mkdtemp(join(tmpdir(), "platform-gh-step-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  await mkdir(bin);
  const responsePath = join(root, "response.json");
  const outputPath = join(root, "github-output");
  await writeFile(responsePath, JSON.stringify(response));
  const gh = join(bin, "gh");
  await writeFile(
    gh,
    fail
      ? "#!/bin/sh\nexit 42\n"
      : "#!/bin/sh\nset -eu\ncat \"$FAKE_GH_RESPONSE\"\n",
  );
  await chmod(gh, 0o755);
  const child = Bun.spawn(["/bin/bash", "--noprofile", "--norc", "-c", run], {
    cwd: root,
    env: {
      ...env,
      FAKE_GH_RESPONSE: responsePath,
      GH_TOKEN: "fixture-token",
      GITHUB_OUTPUT: outputPath,
      GITHUB_REPOSITORY: "collinbentley1/cdbentley",
      PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      RUNNER_TEMP: root,
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return {
    exitCode,
    output: await readFile(outputPath, "utf8"),
    stderr,
  };
}

async function executeReconcileStep(
  run: string,
  pullRequest: JsonObject,
  revision: JsonObject,
  service: JsonObject,
): Promise<{ exitCode: number; mutations: string; stderr: string }> {
  const root = await mkdtemp(join(tmpdir(), "platform-reconcile-step-"));
  temporaryRoots.push(root);
  const bin = join(root, "bin");
  await mkdir(bin);
  const prPath = join(root, "pr.json");
  const revisionPath = join(root, "revision.json");
  const servicePath = join(root, "service.json");
  const mutations = join(root, "mutations.txt");
  await writeFile(prPath, JSON.stringify(pullRequest));
  await writeFile(revisionPath, JSON.stringify(revision));
  await writeFile(servicePath, JSON.stringify(service));
  await writeFile(mutations, "");
  const gh = join(bin, "gh");
  const gcloud = join(bin, "gcloud");
  const curl = join(bin, "curl");
  await writeFile(gh, "#!/bin/sh\nset -eu\ncat \"$FAKE_PR_JSON\"\n");
  await writeFile(
    gcloud,
    [
      "#!/bin/sh",
      "set -eu",
      "case \"$*\" in",
      "  *\"run services describe\"*) cat \"$FAKE_SERVICE_JSON\" ;;",
      "  *\"run revisions describe\"*) cat \"$FAKE_REVISION_JSON\" ;;",
      "  *\"run services update-traffic\"*) jq '.status.traffic = []' \"$FAKE_SERVICE_JSON\" > \"$FAKE_SERVICE_JSON.next\"; mv \"$FAKE_SERVICE_JSON.next\" \"$FAKE_SERVICE_JSON\"; printf 'update-traffic\\n' >> \"$FAKE_MUTATIONS\" ;;",
      "  *\"run services update\"*) printf 'seal\\n' >> \"$FAKE_MUTATIONS\" ;;",
      "  *\"auth print-access-token\"*) printf 'fixture-access-token\\n' ;;",
      "  *\"run services list\"*) echo 'PERMISSION_DENIED' >&2; exit 1 ;;",
      "  *) echo \"unexpected gcloud argv: $*\" >&2; exit 64 ;;",
      "esac",
      "",
    ].join("\n"),
  );
  await writeFile(
    curl,
    [
      "#!/bin/sh",
      "set -eu",
      "output=",
      "all_args=$*",
      "while [ $# -gt 0 ]; do",
      "  if [ \"$1\" = --output ]; then shift; output=$1; fi",
      "  shift",
      "done",
      "case \"$all_args\" in *'/livez'*) printf '404'; exit 0 ;; esac",
      "test -n \"$output\"",
      "printf '%s\\n' '{\"reconciling\":false,\"ingress\":\"INGRESS_TRAFFIC_INTERNAL_ONLY\",\"invokerIamDisabled\":false}' > \"$output\"",
      "",
    ].join("\n"),
  );
  await chmod(gh, 0o755);
  await chmod(gcloud, 0o755);
  await chmod(curl, 0o755);
  const child = Bun.spawn(["/bin/bash", "--noprofile", "--norc", "-c", run], {
    cwd: root,
    env: {
      FAKE_MUTATIONS: mutations,
      FAKE_PR_JSON: prPath,
      FAKE_REVISION_JSON: revisionPath,
      FAKE_SERVICE_JSON: servicePath,
      GH_TOKEN: "fixture-token",
      GITHUB_REPOSITORY: "collinbentley1/cdbentley",
      PATH: `${bin}:${process.env.PATH ?? "/usr/bin:/bin"}`,
      RUNNER_TEMP: root,
      EXPECTED_PLATFORM_WORKFLOW_SHA: platformWorkflowSha,
      EXPECTED_PREVIEW_IMAGE_NAME: "us-east4-docker.pkg.dev/cdbentley/site-preview/cdbentley",
      EXPECTED_PREVIEW_RUNTIME_SERVICE_ACCOUNT: "cloud-run-preview@cdbentley.iam.gserviceaccount.com",
      EXPECTED_PRODUCTION_IMAGE_NAME: "us-east4-docker.pkg.dev/cdbentley/site/cdbentley",
      EXPECTED_PROJECT_NUMBER: "882468538648",
      EXPECTED_REPOSITORY: "collinbentley1/cdbentley",
      PARITY_POLICY_ROOT: repoRoot,
      PLATFORM_WORKFLOW_SHA: platformWorkflowSha,
      PROJECT_ID: "cdbentley",
      REGION: "us-east4",
      REPOSITORY_ID: "1255553151",
      SERVICE_NAME: "cdbentley",
    },
    stderr: "pipe",
    stdout: "ignore",
  });
  const [exitCode, stderr] = await Promise.all([
    child.exited,
    new Response(child.stderr).text(),
  ]);
  return {
    exitCode,
    mutations: await readFile(mutations, "utf8"),
    stderr,
  };
}
