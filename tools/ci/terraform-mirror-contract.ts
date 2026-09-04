export type TerraformMirrorIdentity = {
  readonly expectedPlatformSha?: string | undefined;
  readonly githubRepositoryId: string;
  readonly name?: string | undefined;
  readonly projectId: string;
  readonly serviceName?: string | undefined;
};

export type TerraformMirrorSources = {
  readonly bootstrapMain: string;
  readonly bootstrapOutputs: string;
  readonly bootstrapVariables: string;
  readonly bootstrapVersions: string;
  readonly productionMain: string;
  readonly productionOutputs: string;
  readonly productionVariables: string;
  readonly productionVersions: string;
};

type ReviewedTerraformContract = {
  readonly artifactRegistryDescription?: string;
  readonly artifactRegistryRepositoryId?: string;
  // Terraform an application may carry in prod/main.tf ALONGSIDE the platform
  // module. The whole file is compared against module + these, so an
  // application cannot add a resource the platform has not reviewed, and the
  // platform cannot silently drop one the application depends on.
  //
  // Held comment-free: the comparison runs on parsed documents, which strip
  // comments, so this pins what the resources DO and leaves the application
  // free to explain them in prose.
  readonly additionalProductionResources?: string;
  readonly containerEnv?: readonly (readonly [string, string | TerraformExpression])[];
  readonly firestoreDatabase?: readonly (readonly [string, string])[];
  readonly githubRepo?: string;
  readonly name?: string;
  readonly previewIngress: "INGRESS_TRAFFIC_ALL" | "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER";
  readonly projectId?: string;
  readonly requiredServicesOverride: readonly string[] | null;
  readonly runtimeDescription?: string;
  readonly runtimeProjectRolesOverride: readonly string[] | null;
  readonly runtimeSecretAccessorIds: readonly string[];
  readonly runtimeSecretIds: readonly string[];
  readonly runtimeSecretVersionAdderIds: readonly string[];
  readonly serviceName?: string;
  readonly stateBucketName?: string;
};

type TerraformExpression = {
  // Reviewed HCL, not application input. This exists for public values that are
  // created in the same plan (for example a reCAPTCHA site key) and therefore
  // must be wired by resource identity rather than copied as a string.
  readonly expression: string;
};

const defaultContract: ReviewedTerraformContract = {
  previewIngress: "INGRESS_TRAFFIC_ALL",
  requiredServicesOverride: null,
  runtimeProjectRolesOverride: null,
  runtimeSecretAccessorIds: [],
  runtimeSecretIds: [],
  runtimeSecretVersionAdderIds: [],
};

const reviewedContracts: Readonly<Record<string, ReviewedTerraformContract>> = {
  "1255553151": {
    ...defaultContract,
    artifactRegistryDescription: "Container images for the cdbentley personal site.",
    artifactRegistryRepositoryId: "site",
    githubRepo: "cdbentley",
    name: "cdbentley",
    projectId: "cdbentley",
    serviceName: "cdbentley",
    stateBucketName: "cdbentley-tfstate-882468538648",
  },
  "1025243085": {
    // Reviewed verbatim: the Firestore field TTL policies that make `expiresAt`
    // enforceable, and the Identity Platform/reCAPTCHA configuration behind the
    // waitlist ownership flow. The trusted platform production root is their
    // live owner; this consumer mirror remains an exact, reviewable declaration
    // of the application contract. API enablement belongs only to bootstrap
    // state and is intentionally not duplicated here.
    additionalProductionResources: `resource "google_firestore_field" "waitlist_entry_ttl" {
  project    = var.project_id
  database   = "(default)"
  collection = "waitlist"
  field      = "expiresAt"

  ttl_config {}

  index_config {}

  depends_on = [module.site]
}

resource "google_firestore_field" "waitlist_quota_ttl" {
  project    = var.project_id
  database   = "(default)"
  collection = "waitlist_quota"
  field      = "expiresAt"

  ttl_config {}

  index_config {}

  depends_on = [module.site]
}

resource "google_identity_platform_config" "default" {
  project = var.project_id

  sign_in {
    allow_duplicate_emails = false

    email {
      enabled           = true
      password_required = false
    }
  }

  authorized_domains = [
    "medlock.ai",
    "www.medlock.ai",
  ]
}

resource "google_recaptcha_enterprise_key" "waitlist" {
  project      = var.project_id
  display_name = "Medlock waitlist ownership"

  deletion_policy = "PREVENT"

  web_settings {
    integration_type  = "SCORE"
    allow_all_domains = false
    allow_amp_traffic = false
    allowed_domains   = ["medlock.ai"]
  }
}`,
    artifactRegistryDescription: "Container images for Medlock.",
    artifactRegistryRepositoryId: "site",
    containerEnv: [
      [
        "ALLOWED_HOSTS",
        "medlock.ai,www.medlock.ai,mcp.medlock.ai,healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app,*.run.app",
      ],
      [
        "ALLOWED_ORIGINS",
        "https://medlock.ai,https://www.medlock.ai,https://mcp.medlock.ai,https://chat.openai.com,https://claude.ai,https://*.run.app",
      ],
      ["CANONICAL_HOST", "medlock.ai"],
      [
        "LEGACY_HOSTS",
        "healthmcp.ai,www.healthmcp.ai,healthmcp.app,www.healthmcp.app",
      ],
      ["MEDLOCK_VERSION", "0.2.0"],
      ["WAITLIST_BACKEND", "firestore"],
      ["IDENTITY_PLATFORM_AUDIENCE", "medlock-1025243085"],
      ["IDENTITY_PLATFORM_CONTINUE_URL", "https://medlock.ai/api/waitlist/confirm"],
      ["RECAPTCHA_PROJECT_ID", "medlock-1025243085"],
      ["RECAPTCHA_SITE_KEY", { expression: "google_recaptcha_enterprise_key.waitlist.name" }],
    ],
    firestoreDatabase: [
      ["name", "(default)"],
      ["location_id", "nam5"],
      ["runtime_collection_env_name", "FIRESTORE_COLLECTION"],
      ["runtime_collection_env_value", "waitlist"],
    ],
    githubRepo: "healthmcp",
    name: "medlock",
    previewIngress: "INGRESS_TRAFFIC_ALL",
    projectId: "medlock-1025243085",
    requiredServicesOverride: [
      "artifactregistry.googleapis.com",
      "cloudasset.googleapis.com",
      "cloudresourcemanager.googleapis.com",
      "firestore.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "identitytoolkit.googleapis.com",
      "recaptchaenterprise.googleapis.com",
      "run.googleapis.com",
      "secretmanager.googleapis.com",
      "serviceusage.googleapis.com",
      "storage.googleapis.com",
      "sts.googleapis.com",
    ],
    runtimeSecretAccessorIds: ["waitlist-identity-keyset"],
    runtimeDescription: "Runtime identity for the Medlock Cloud Run services.",
    runtimeSecretIds: ["waitlist-identity-keyset"],
    runtimeSecretVersionAdderIds: ["waitlist-identity-keyset"],
    runtimeProjectRolesOverride: ["roles/datastore.user"],
    serviceName: "medlock",
    stateBucketName: "medlock-tfstate-1025243085",
  },
  "711292980": {
    artifactRegistryDescription: "Container images for the Runsetta API.",
    artifactRegistryRepositoryId: "api",
    containerEnv: [
      ["RUNSETTA_OFFLINE", "1"],
      ["RUNSETTA_TTS_MODEL", "gpt-4o-mini-tts"],
      ["RUNSETTA_TTS_VOICE", "marin"],
    ],
    githubRepo: "runsetta",
    name: "runsetta",
    previewIngress: "INGRESS_TRAFFIC_ALL",
    projectId: "runsetta",
    requiredServicesOverride: [
      "artifactregistry.googleapis.com",
      "cloudasset.googleapis.com",
      "cloudresourcemanager.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "run.googleapis.com",
      "secretmanager.googleapis.com",
      "serviceusage.googleapis.com",
      "storage.googleapis.com",
      "sts.googleapis.com",
    ],
    runtimeSecretAccessorIds: [],
    runtimeDescription: "Runtime identity for the Runsetta Cloud Run services.",
    runtimeSecretIds: [
      "openai-api-key",
      "spotify-client-id",
      "spotify-client-secret",
      "spotify-redirect-uri",
    ],
    runtimeSecretVersionAdderIds: [],
    runtimeProjectRolesOverride: null,
    serviceName: "runsetta",
    stateBucketName: "runsetta-tfstate-601124730704",
  },
  "280932482": {
    ...defaultContract,
    artifactRegistryDescription: "Container images for the Critical History Map.",
    artifactRegistryRepositoryId: "site",
    githubRepo: "critical-history",
    name: "critical-history",
    previewIngress: "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
    projectId: "critical-history-16823277",
    requiredServicesOverride: [
      "artifactregistry.googleapis.com",
      "certificatemanager.googleapis.com",
      "cloudasset.googleapis.com",
      "cloudresourcemanager.googleapis.com",
      "compute.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "run.googleapis.com",
      "serviceusage.googleapis.com",
      "storage.googleapis.com",
      "sts.googleapis.com",
    ],
    serviceName: "critical-history",
    stateBucketName: "critical-history-tfstate-422714632513",
  },
};

const previewOperatorVariableDescription =
  "Deprecated transition-only preview operator email retained for input compatibility; receives no IAM grant.";
const previewOperatorOutputDescription =
  "Retired transition-only preview operator service account; receives no steady-state operational grants.";
const forbiddenPreMigrationWorkflowShas = new Set([
  "734d0cd02187f88c6e91263f127dc3f4c0709feb",
  "1378a3e81a5e74c71f2adfd5548b430bb008490e",
  "37bd4b1beea8802ec85c38d69ea08d5992c75a50",
  "42435a3c4c5c063a342765ef7c85047224217fe2",
  "7f01d9f008a7757df12f13ac8fa0f261600cf21a",
  "4f032955477c26b942fdd4f1b01f5272380390ea",
  "92c73184bc527388b5e10ccb5e4f0222a84e68b5",
  "33ab9b9a5f3d8a0553372980c22540cad001f776",
]);

export function validateTerraformMirrorContract(
  identity: TerraformMirrorIdentity,
  sources: TerraformMirrorSources,
): string[] {
  const failures: string[] = [];
  const contract = reviewedContracts[identity.githubRepositoryId] ?? defaultContract;

  if (!identity.name) {
    failures.push(".platform/config.json name is required by the Terraform mirror contract");
  }
  if (!identity.serviceName) {
    failures.push(".platform/config.json serviceName is required by the Terraform mirror contract");
  }
  if (
    identity.expectedPlatformSha !== undefined &&
    !/^[0-9a-f]{40}$/.test(identity.expectedPlatformSha)
  ) {
    failures.push("expected platform workflow SHA must be one full lowercase commit SHA");
  }

  if (contract.name !== undefined && identity.name !== contract.name) {
    failures.push(
      `.platform/config.json name must remain ${JSON.stringify(contract.name)} for repository ID ${identity.githubRepositoryId}`,
    );
  }
  if (contract.projectId !== undefined && identity.projectId !== contract.projectId) {
    failures.push(
      `.platform/config.json projectId must remain ${JSON.stringify(contract.projectId)} for repository ID ${identity.githubRepositoryId}`,
    );
  }
  if (contract.serviceName !== undefined && identity.serviceName !== contract.serviceName) {
    failures.push(
      `.platform/config.json serviceName must remain ${JSON.stringify(contract.serviceName)} for repository ID ${identity.githubRepositoryId}`,
    );
  }

  const parsed = {
    bootstrapMain: parseDocument("infra/terraform/bootstrap/main.tf", sources.bootstrapMain, failures),
    bootstrapOutputs: parseDocument(
      "infra/terraform/bootstrap/outputs.tf",
      sources.bootstrapOutputs,
      failures,
    ),
    bootstrapVariables: parseDocument(
      "infra/terraform/bootstrap/variables.tf",
      sources.bootstrapVariables,
      failures,
    ),
    bootstrapVersions: parseDocument(
      "infra/terraform/bootstrap/versions.tf",
      sources.bootstrapVersions,
      failures,
    ),
    productionMain: parseDocument("infra/terraform/prod/main.tf", sources.productionMain, failures),
    productionOutputs: parseDocument(
      "infra/terraform/prod/outputs.tf",
      sources.productionOutputs,
      failures,
    ),
    productionVariables: parseDocument(
      "infra/terraform/prod/variables.tf",
      sources.productionVariables,
      failures,
    ),
    productionVersions: parseDocument(
      "infra/terraform/prod/versions.tf",
      sources.productionVersions,
      failures,
    ),
  };

  const productionModule = requireUniqueNamedBlock(
    parsed.productionMain,
    "module",
    "site",
    "infra/terraform/prod/main.tf",
    failures,
  );
  const productionPlatformSha = productionModule
    ? requirePlatformModuleSource(
        productionModule,
        "cloud-run-service",
        "infra/terraform/prod/main.tf",
        failures,
      )
    : undefined;
  if (productionModule) {
    requireExactTopLevelAttribute(
      productionModule,
      "deployment_parity_reader_service_account_email",
      "var.deployment_parity_reader_service_account_email",
      "infra/terraform/prod/main.tf module site must pass deployment_parity_reader_service_account_email exactly once",
      failures,
    );
    requireExactTopLevelAttribute(
      productionModule,
      "preview_commit_service_account_email",
      "var.preview_commit_service_account_email",
      "infra/terraform/prod/main.tf module site must pass preview_commit_service_account_email exactly once",
      failures,
    );
    requireExactTopLevelAttribute(
      productionModule,
      "preview_ingress",
      "var.preview_ingress",
      "infra/terraform/prod/main.tf module site must pass preview_ingress = var.preview_ingress exactly once",
      failures,
    );
    requireExactTopLevelAttribute(
      productionModule,
      "runtime_secret_version_adder_ids",
      "var.runtime_secret_version_adder_ids",
      "infra/terraform/prod/main.tf module site must pass runtime_secret_version_adder_ids = var.runtime_secret_version_adder_ids exactly once",
      failures,
    );
    requireExactTopLevelAttribute(
      productionModule,
      "runtime_secret_ids",
      "var.runtime_secret_ids",
      "infra/terraform/prod/main.tf module site must pass runtime_secret_ids = var.runtime_secret_ids exactly once",
      failures,
    );
    requireExactTopLevelAttribute(
      productionModule,
      "runtime_secret_accessor_ids",
      "var.runtime_secret_accessor_ids",
      "infra/terraform/prod/main.tf module site must pass runtime_secret_accessor_ids = var.runtime_secret_accessor_ids exactly once",
      failures,
    );
    if (
      productionPlatformSha &&
      identity.expectedPlatformSha !== undefined &&
      productionPlatformSha !== identity.expectedPlatformSha
    ) {
      failures.push(
        "infra/terraform/prod/main.tf module source must match the active reusable workflow SHA",
      );
    }
    if (productionPlatformSha && identity.name && identity.serviceName) {
      const expectedProductionModule = renderProductionModule(
        identity,
        contract,
        productionPlatformSha,
      );
      if (compactHcl(productionModule) !== compactHcl(expectedProductionModule)) {
        failures.push(
          "infra/terraform/prod/main.tf module site must exactly match the reviewed repository-specific platform contract",
        );
      }
      const expectedProductionFile = contract.additionalProductionResources === undefined
        ? expectedProductionModule
        : `${expectedProductionModule}\n${contract.additionalProductionResources}`;
      if (compactHcl(parsed.productionMain) !== compactHcl(expectedProductionFile)) {
        failures.push(
          "infra/terraform/prod/main.tf must contain only the exact reviewed repository-specific platform module and reviewed additional resources",
        );
      }
    }
  }

  requireCanonicalNamedBlock(
    parsed.productionVariables,
    "variable",
    "preview_ingress",
    previewIngressVariable(contract.previewIngress),
    "infra/terraform/prod/variables.tf preview_ingress must match the reviewed repository-specific ingress contract",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.productionVariables,
    "variable",
    "runtime_secret_ids",
    secretSetVariable("runtime_secret_ids", contract.runtimeSecretIds),
    "infra/terraform/prod/variables.tf runtime_secret_ids must match the reviewed repository-specific set",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.productionVariables,
    "variable",
    "runtime_secret_accessor_ids",
    secretSetVariable("runtime_secret_accessor_ids", contract.runtimeSecretAccessorIds),
    "infra/terraform/prod/variables.tf runtime_secret_accessor_ids must match the reviewed repository-specific set and subset validation",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.productionVariables,
    "variable",
    "runtime_secret_version_adder_ids",
    secretSetVariable(
      "runtime_secret_version_adder_ids",
      contract.runtimeSecretVersionAdderIds,
    ),
    "infra/terraform/prod/variables.tf runtime_secret_version_adder_ids must match the reviewed repository-specific set and subset validation",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.productionVariables,
    "variable",
    "deployment_parity_reader_service_account_email",
    simpleVariable(
      "deployment_parity_reader_service_account_email",
      "Read-only deployment parity service account email.",
      "string",
      JSON.stringify(`gha-deploy-parity@${identity.projectId}.iam.gserviceaccount.com`),
    ),
    "infra/terraform/prod/variables.tf deployment parity reader input must remain the exact read-only identity",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.productionVariables,
    "variable",
    "preview_commit_service_account_email",
    simpleVariable(
      "preview_commit_service_account_email",
      "Preview traffic/exposure transaction service account email.",
      "string",
      JSON.stringify(`gha-preview-commit@${identity.projectId}.iam.gserviceaccount.com`),
    ),
    "infra/terraform/prod/variables.tf preview commit identity must remain exact",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.productionVariables,
    "variable",
    "preview_operator_service_account_email",
    previewOperatorVariable(identity.projectId),
    "infra/terraform/prod/variables.tf preview operator input must retain the retired no-grant semantics",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.bootstrapOutputs,
    "output",
    "deployment_parity_reader_service_account_email",
    outputBlock(
      "deployment_parity_reader_service_account_email",
      "Read-only identity used by exact deployment workflows for DHI parity checks.",
      "module.bootstrap.deployment_parity_reader_service_account_email",
    ),
    "infra/terraform/bootstrap/outputs.tf deployment parity reader output must remain exact",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.bootstrapOutputs,
    "output",
    "preview_commit_service_account_email",
    outputBlock(
      "preview_commit_service_account_email",
      "Exact-workflow transaction identity scoped to preview traffic and exposure changes only.",
      "module.bootstrap.preview_commit_service_account_email",
    ),
    "infra/terraform/bootstrap/outputs.tf preview commit identity output must remain exact",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.bootstrapOutputs,
    "output",
    "preview_iam_audit_service_account_email",
    outputBlock(
      "preview_iam_audit_service_account_email",
      "Exact-workflow, read-only cross-project preview runtime IAM auditor.",
      "module.bootstrap.preview_iam_audit_service_account_email",
    ),
    "infra/terraform/bootstrap/outputs.tf preview IAM auditor output must remain exact",
    failures,
  );
  requireCanonicalNamedBlock(
    parsed.bootstrapOutputs,
    "output",
    "preview_operator_service_account_email",
    previewOperatorOutput(),
    "infra/terraform/bootstrap/outputs.tf preview operator output must retain the retired no-grant semantics",
    failures,
  );

  const bootstrapModule = requireUniqueNamedBlock(
    parsed.bootstrapMain,
    "module",
    "bootstrap",
    "infra/terraform/bootstrap/main.tf",
    failures,
  );
  const bootstrapPlatformSha = bootstrapModule
    ? requirePlatformModuleSource(
        bootstrapModule,
        "bootstrap",
        "infra/terraform/bootstrap/main.tf",
        failures,
      )
    : undefined;
  if (
    productionPlatformSha &&
    bootstrapPlatformSha &&
    productionPlatformSha !== bootstrapPlatformSha
  ) {
    failures.push("bootstrap and production module sources must use the same platform SHA");
  }
  if (
    bootstrapPlatformSha &&
    identity.expectedPlatformSha !== undefined &&
    bootstrapPlatformSha !== identity.expectedPlatformSha
  ) {
    failures.push(
      "infra/terraform/bootstrap/main.tf module source must match the active reusable workflow SHA",
    );
  }
  if (bootstrapModule) {
    const requiredServices = topLevelAttributeValues(bootstrapModule, "required_services");
    if (contract.requiredServicesOverride === null) {
      if (requiredServices.length !== 0) {
        failures.push(
          "infra/terraform/bootstrap/main.tf must rely on the reviewed base required_services set for this repository",
        );
      }
    } else {
      const expected = compactHcl(renderStringList(contract.requiredServicesOverride));
      if (requiredServices.length !== 1 || compactHcl(requiredServices[0] ?? "") !== expected) {
        failures.push(
          "infra/terraform/bootstrap/main.tf required_services must match the reviewed repository-specific API set",
        );
      }
    }

    const runtimeProjectRoles = topLevelAttributeValues(
      bootstrapModule,
      "runtime_project_roles",
    );
    if (contract.runtimeProjectRolesOverride === null) {
      if (runtimeProjectRoles.length !== 0) {
        failures.push(
          "infra/terraform/bootstrap/main.tf must rely on the reviewed empty runtime_project_roles default for this repository",
        );
      }
    } else {
      const expected = compactHcl(renderStringList(contract.runtimeProjectRolesOverride));
      if (runtimeProjectRoles.length !== 1 || compactHcl(runtimeProjectRoles[0] ?? "") !== expected) {
        failures.push(
          "infra/terraform/bootstrap/main.tf runtime_project_roles must match the reviewed repository-specific role set",
        );
      }
    }

    if (bootstrapPlatformSha && identity.name) {
      if (validateActiveWorkflowSha(bootstrapModule, bootstrapPlatformSha, failures)) {
        const expectedBootstrapModule = renderBootstrapModule(
          identity,
          contract,
          bootstrapPlatformSha,
        );
        if (compactHcl(bootstrapModule) !== compactHcl(expectedBootstrapModule)) {
          failures.push(
            "infra/terraform/bootstrap/main.tf module bootstrap must exactly match the reviewed repository-specific platform contract",
          );
        }
        if (compactHcl(parsed.bootstrapMain) !== compactHcl(expectedBootstrapModule)) {
          failures.push(
            "infra/terraform/bootstrap/main.tf must contain only the exact reviewed repository-specific platform module",
          );
        }
      }
    }
  }

  if (identity.name && identity.serviceName) {
    const exactFiles = [
      [
        "infra/terraform/bootstrap/variables.tf",
        parsed.bootstrapVariables,
        renderBootstrapVariables(identity, contract),
      ],
      [
        "infra/terraform/bootstrap/outputs.tf",
        parsed.bootstrapOutputs,
        renderBootstrapOutputs(),
      ],
      [
        "infra/terraform/bootstrap/versions.tf",
        parsed.bootstrapVersions,
        renderBootstrapVersions(identity, contract),
      ],
      [
        "infra/terraform/prod/variables.tf",
        parsed.productionVariables,
        renderProductionVariables(identity, contract),
      ],
      ["infra/terraform/prod/outputs.tf", parsed.productionOutputs, renderProductionOutputs()],
      [
        "infra/terraform/prod/versions.tf",
        parsed.productionVersions,
        renderProductionVersions(identity, contract),
      ],
    ] as const;
    for (const [path, actual, expected] of exactFiles) {
      if (compactHcl(actual) !== compactHcl(expected)) {
        failures.push(`${path} must exactly match the reviewed repository-specific mirror contract`);
      }
    }
  }

  for (const [path, source] of [
    ["infra/terraform/prod/variables.tf", sources.productionVariables],
    ["infra/terraform/bootstrap/outputs.tf", sources.bootstrapOutputs],
  ] as const) {
    if (source.includes("downloadArtifacts")) {
      failures.push(`${path} must not retain the retired preview-operator downloadArtifacts claim`);
    }
  }

  return failures;
}

function parseDocument(path: string, source: string, failures: string[]): string {
  let output = "";
  let state: "normal" | "string" | "line" | "block" = "normal";
  let escaped = false;

  for (let index = 0; index < source.length; index += 1) {
    const character = source[index]!;
    const next = source[index + 1];

    if (state === "line") {
      if (character === "\n") {
        state = "normal";
        output += "\n";
      } else {
        output += " ";
      }
      continue;
    }
    if (state === "block") {
      if (character === "*" && next === "/") {
        output += "  ";
        index += 1;
        state = "normal";
      } else {
        output += character === "\n" ? "\n" : " ";
      }
      continue;
    }
    if (state === "string") {
      output += character;
      if (character === "\n") {
        failures.push(`${path} contains a multiline quoted string that the strict mirror parser rejects`);
        state = "normal";
        escaped = false;
      } else if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        state = "normal";
      }
      continue;
    }

    if (character === '"') {
      state = "string";
      output += character;
    } else if (character === "#") {
      state = "line";
      output += " ";
    } else if (character === "/" && next === "/") {
      state = "line";
      output += "  ";
      index += 1;
    } else if (character === "/" && next === "*") {
      state = "block";
      output += "  ";
      index += 1;
    } else if (character === "<" && next === "<") {
      failures.push(`${path} must not use heredocs in the security-critical Terraform mirror`);
      output += "<<";
      index += 1;
    } else {
      output += character;
    }
  }

  if (state === "block" || state === "string") {
    failures.push(`${path} contains an unterminated ${state === "block" ? "block comment" : "string"}`);
  }
  return output;
}

function requireUniqueNamedBlock(
  source: string,
  kind: string,
  name: string,
  path: string,
  failures: string[],
): string | undefined {
  const blocks = namedBlocks(source, kind, name);
  if (blocks.length !== 1) {
    failures.push(`${path} must contain exactly one active ${kind} ${JSON.stringify(name)}`);
    return undefined;
  }
  return blocks[0];
}

function requireCanonicalNamedBlock(
  source: string,
  kind: string,
  name: string,
  expected: string,
  message: string,
  failures: string[],
): void {
  const blocks = namedBlocks(source, kind, name);
  if (blocks.length !== 1 || compactHcl(blocks[0] ?? "") !== compactHcl(expected)) {
    failures.push(message);
  }
}

function namedBlocks(source: string, kind: string, name: string): string[] {
  const pattern = new RegExp(
    "^\\s*" + escapeRegExp(kind) + "\\s+\"" + escapeRegExp(name) + "\"\\s*\\{\\s*$",
    "gm",
  );
  const blocks: string[] = [];
  for (const match of source.matchAll(pattern)) {
    const start = match.index!;
    const openingBrace = source.indexOf("{", start);
    const end = matchingBrace(source, openingBrace);
    if (end !== -1) {
      blocks.push(source.slice(start, end + 1));
    }
  }
  return blocks;
}

function matchingBrace(source: string, openingBrace: number): number {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = openingBrace; index < source.length; index += 1) {
    const character = source[index]!;
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
    } else if (character === "{") {
      depth += 1;
    } else if (character === "}") {
      depth -= 1;
      if (depth === 0) {
        return index;
      }
    }
  }
  return -1;
}

function requireExactTopLevelAttribute(
  block: string,
  name: string,
  expected: string,
  message: string,
  failures: string[],
): void {
  const values = topLevelAttributeValues(block, name);
  if (values.length !== 1 || compactHcl(values[0] ?? "") !== compactHcl(expected)) {
    failures.push(message);
  }
}

function topLevelAttributeValues(block: string, expectedName: string): string[] {
  const values: string[] = [];
  let braceDepth = 0;
  let index = 0;
  let lineStart = true;
  let inString = false;
  let escaped = false;

  while (index < block.length) {
    if (lineStart && braceDepth === 1 && !inString) {
      let cursor = index;
      while (block[cursor] === " " || block[cursor] === "\t") cursor += 1;
      const identifier = block.slice(cursor).match(/^([A-Za-z_][A-Za-z0-9_]*)\s*=/);
      if (identifier?.[1] === expectedName) {
        const equals = block.indexOf("=", cursor + identifier[1].length);
        const expressionStart = skipHorizontalWhitespace(block, equals + 1);
        const expressionEnd = findExpressionEnd(block, expressionStart);
        values.push(block.slice(expressionStart, expressionEnd).trim());
      }
    }

    const character = block[index]!;
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
    } else if (character === '"') {
      inString = true;
    } else if (character === "{") {
      braceDepth += 1;
    } else if (character === "}") {
      braceDepth -= 1;
    }
    lineStart = character === "\n";
    index += 1;
  }

  return values;
}

function findExpressionEnd(source: string, start: number): number {
  const stack: string[] = [];
  let inString = false;
  let escaped = false;
  for (let index = start; index < source.length; index += 1) {
    const character = source[index]!;
    if (inString) {
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
      continue;
    }
    if (character === '"') {
      inString = true;
    } else if (character === "[" || character === "{" || character === "(") {
      stack.push(character);
    } else if (character === "]" || character === "}" || character === ")") {
      if (stack.length === 0) return index;
      stack.pop();
    } else if (character === "\n" && stack.length === 0) {
      return index;
    }
  }
  return source.length;
}

function compactHcl(source: string): string {
  let result = "";
  let inString = false;
  let escaped = false;
  for (const character of source) {
    if (inString) {
      result += character;
      if (escaped) {
        escaped = false;
      } else if (character === "\\") {
        escaped = true;
      } else if (character === '"') {
        inString = false;
      }
    } else if (character === '"') {
      inString = true;
      result += character;
    } else if (!/\s/.test(character)) {
      result += character;
    }
  }
  return result;
}

function requirePlatformModuleSource(
  block: string,
  moduleName: "bootstrap" | "cloud-run-service",
  path: string,
  failures: string[],
): string | undefined {
  const values = topLevelAttributeValues(block, "source");
  const pattern = new RegExp(
    '^"github\\.com/collinbentley1/platform//terraform/modules/' +
      escapeRegExp(moduleName) +
      '\\?ref=([0-9a-f]{40})"$',
  );
  const match = values.length === 1 ? compactHcl(values[0] ?? "").match(pattern) : null;
  if (!match) {
    failures.push(
      `${path} module must contain exactly one top-level canonical ${moduleName} source pinned to a full lowercase platform commit SHA`,
    );
    return undefined;
  }

  const sha = match[1]!;
  if (forbiddenPreMigrationWorkflowShas.has(sha)) {
    failures.push(`${path} module source must not restore a retired pre-migration platform SHA`);
  }
  return sha;
}

function validateActiveWorkflowSha(
  block: string,
  platformSha: string,
  failures: string[],
): boolean {
  const values = topLevelAttributeValues(block, "active_workflow_sha");
  if (values.length !== 1) {
    failures.push(
      "infra/terraform/bootstrap/main.tf module bootstrap must define active_workflow_sha exactly once at top level",
    );
    return false;
  }
  const active = parseQuotedString(values[0] ?? "");
  if (active === undefined || !/^[0-9a-f]{40}$/.test(active)) {
    failures.push(
      "infra/terraform/bootstrap/main.tf active_workflow_sha must be one quoted full lowercase commit SHA",
    );
    return false;
  }
  if (forbiddenPreMigrationWorkflowShas.has(active)) {
    failures.push("infra/terraform/bootstrap/main.tf active_workflow_sha must not restore a retired pre-migration SHA");
  }
  if (active !== platformSha) {
    failures.push(
      "infra/terraform/bootstrap/main.tf consumer mirror active_workflow_sha must be the module platform SHA",
    );
  }
  for (const transition of topLevelAttributeValues(block, "transition_workflow_sha")) {
    failures.push(
      "infra/terraform/bootstrap/main.tf transition_workflow_sha must be absent in the consumer steady-state mirror",
    );
    const sha = parseQuotedString(transition);
    if (sha !== undefined && forbiddenPreMigrationWorkflowShas.has(sha)) {
      failures.push("infra/terraform/bootstrap/main.tf transition_workflow_sha must not restore a retired pre-migration SHA");
    }
  }
  return true;
}

function parseQuotedString(expression: string): string | undefined {
  const trimmed = expression.trim();
  if (!/^"(?:[^"\\]|\\.)*"$/.test(trimmed)) return undefined;
  try {
    const parsed: unknown = JSON.parse(trimmed);
    return typeof parsed === "string" ? parsed : undefined;
  } catch {
    return undefined;
  }
}

function renderProductionModule(
  identity: TerraformMirrorIdentity,
  contract: ReviewedTerraformContract,
  platformSha: string,
): string {
  const lines = [
    'module "site" {',
    `source = "github.com/collinbentley1/platform//terraform/modules/cloud-run-service?ref=${platformSha}"`,
    "providers = {",
    "google = google",
    "google.no_attribution = google.no_attribution",
    "}",
    `app = ${JSON.stringify(identity.name)}`,
    "project_id = var.project_id",
    "region = var.region",
    "service_name = var.service_name",
    "artifact_registry_repository_id = var.artifact_registry_repository_id",
  ];
  lines.push(
    `artifact_registry_description = ${JSON.stringify(
      contract.artifactRegistryDescription ?? `Container images for ${identity.name}.`,
    )}`,
  );
  lines.push(
    "bootstrap_image = var.bootstrap_image",
    "bootstrap_runtime_service_account_email = var.bootstrap_runtime_service_account_email",
    "runtime_service_account_email = var.runtime_service_account_email",
    "preview_runtime_service_account_email = var.preview_runtime_service_account_email",
    "preview_ingress = var.preview_ingress",
    "prod_deploy_service_account_email = var.prod_deploy_service_account_email",
    "prod_publisher_service_account_email = var.prod_publisher_service_account_email",
    "deployment_parity_reader_service_account_email = var.deployment_parity_reader_service_account_email",
    "preview_deploy_service_account_email = var.preview_deploy_service_account_email",
    "preview_commit_service_account_email = var.preview_commit_service_account_email",
    "preview_operator_service_account_email = var.preview_operator_service_account_email",
    "preview_publisher_service_account_email = var.preview_publisher_service_account_email",
  );
  if (contract.containerEnv !== undefined) {
    lines.push(...renderStringMap("container_env", contract.containerEnv));
  }
  lines.push(
    "runtime_secret_ids = var.runtime_secret_ids",
    "runtime_secret_accessor_ids = var.runtime_secret_accessor_ids",
    "runtime_secret_version_adder_ids = var.runtime_secret_version_adder_ids",
  );
  if (contract.firestoreDatabase !== undefined) {
    lines.push(...renderStringMap("firestore_database", contract.firestoreDatabase));
  }
  lines.push("}");
  return lines.join("\n");
}

function renderBootstrapModule(
  identity: TerraformMirrorIdentity,
  contract: ReviewedTerraformContract,
  platformSha: string,
): string {
  const lines = [
    'module "bootstrap" {',
    `source = "github.com/collinbentley1/platform//terraform/modules/bootstrap?ref=${platformSha}"`,
    `app = ${JSON.stringify(identity.name)}`,
    "project_id = var.project_id",
    "region = var.region",
    "state_bucket_name = var.state_bucket_name",
    "bootstrap_state_bucket_name = var.bootstrap_state_bucket_name",
    "state_bucket_location = var.state_bucket_location",
    "github_owner = var.github_owner",
    "github_repo = var.github_repo",
    "github_repository_id = var.github_repository_id",
    `active_workflow_sha = ${JSON.stringify(platformSha)}`,
  ];
  if (contract.requiredServicesOverride !== null) {
    lines.push("required_services = " + renderStringList(contract.requiredServicesOverride));
  }
  if (contract.runtimeProjectRolesOverride !== null) {
    lines.push("runtime_project_roles = " + renderStringList(contract.runtimeProjectRolesOverride));
  }
  lines.push(
    "manage_automatic_default_service_account_grants_policy = var.manage_automatic_default_service_account_grants_policy",
    `runtime_description = ${JSON.stringify(
      contract.runtimeDescription ??
        `Runtime identity for the ${identity.name ?? "application"} Cloud Run services.`,
    )}`,
    "}",
  );
  return lines.join("\n");
}

function renderStringMap(
  name: string,
  entries: readonly (readonly [string, string | TerraformExpression])[],
): string[] {
  return [
    `${name} = {`,
    ...entries.map(([key, value]) => `${key} = ${renderTerraformValue(value)}`),
    "}",
  ];
}

function renderTerraformValue(value: string | TerraformExpression): string {
  if (typeof value === "string") return JSON.stringify(value);
  // Resource-attribute references only. Refuse calls, interpolation, indexing,
  // conditionals, or operators even in this reviewed table so extending the
  // contract cannot quietly turn it into an arbitrary HCL injection surface.
  if (!/^[a-z][a-z0-9_]*(?:\.[a-z][a-z0-9_]*){2}$/.test(value.expression)) {
    throw new Error("reviewed Terraform expression must be one resource attribute reference");
  }
  return value.expression;
}

function renderProductionVariables(
  identity: TerraformMirrorIdentity,
  contract: ReviewedTerraformContract,
): string {
  const projectId = identity.projectId;
  const blocks = [
    simpleVariable("project_id", "Google Cloud project ID.", "string", JSON.stringify(projectId)),
    simpleVariable("region", "Primary Google Cloud region.", "string", '"us-east4"'),
    simpleVariable(
      "service_name",
      "Production Cloud Run service name.",
      "string",
      JSON.stringify(identity.serviceName),
    ),
    simpleVariable(
      "artifact_registry_repository_id",
      "Artifact Registry Docker repository ID.",
      "string",
      JSON.stringify(contract.artifactRegistryRepositoryId ?? "site"),
    ),
    simpleVariable(
      "bootstrap_image",
      "Digest-pinned initial public image used before the application container exists.",
      "string",
      '"us-docker.pkg.dev/cloudrun/container/hello@sha256:9a0e9a5c7a19281e7617991d2fc61809de4973e6e75a10b2f07df3719ffda33c"',
    ),
    simpleVariable(
      "bootstrap_runtime_service_account_email",
      "No-role service account used only by the initial bootstrap image.",
      "string",
      JSON.stringify(`cloud-run-bootstrap@${projectId}.iam.gserviceaccount.com`),
    ),
    simpleVariable(
      "runtime_service_account_email",
      "Cloud Run runtime service account email.",
      "string",
      JSON.stringify(`cloud-run-runtime@${projectId}.iam.gserviceaccount.com`),
    ),
    simpleVariable(
      "preview_runtime_service_account_email",
      "No-data Cloud Run preview runtime service account email.",
      "string",
      JSON.stringify(`cloud-run-preview@${projectId}.iam.gserviceaccount.com`),
    ),
    previewIngressVariable(contract.previewIngress),
    simpleVariable(
      "prod_deploy_service_account_email",
      "Production deploy service account email with exact-repository read access and only declared exact-secret version-add grants.",
      "string",
      JSON.stringify(`gha-prod-deploy@${projectId}.iam.gserviceaccount.com`),
    ),
    simpleVariable(
      "prod_publisher_service_account_email",
      "Artifact Registry-only production publisher service account email.",
      "string",
      JSON.stringify(`gha-prod-publish@${projectId}.iam.gserviceaccount.com`),
    ),
    simpleVariable(
      "deployment_parity_reader_service_account_email",
      "Read-only deployment parity service account email.",
      "string",
      JSON.stringify(`gha-deploy-parity@${projectId}.iam.gserviceaccount.com`),
    ),
    simpleVariable(
      "preview_deploy_service_account_email",
      "Preview deploy service account email with exact-repository read access.",
      "string",
      JSON.stringify(`gha-preview-deploy@${projectId}.iam.gserviceaccount.com`),
    ),
    simpleVariable(
      "preview_commit_service_account_email",
      "Preview traffic/exposure transaction service account email.",
      "string",
      JSON.stringify(`gha-preview-commit@${projectId}.iam.gserviceaccount.com`),
    ),
    previewOperatorVariable(projectId),
    simpleVariable(
      "preview_publisher_service_account_email",
      "Artifact Registry-only preview publisher service account email.",
      "string",
      JSON.stringify(`gha-preview-publish@${projectId}.iam.gserviceaccount.com`),
    ),
    secretSetVariable("runtime_secret_ids", contract.runtimeSecretIds),
    secretSetVariable("runtime_secret_accessor_ids", contract.runtimeSecretAccessorIds),
    secretSetVariable(
      "runtime_secret_version_adder_ids",
      contract.runtimeSecretVersionAdderIds,
    ),
  ];
  return blocks.join("\n\n");
}

function renderBootstrapVariables(
  identity: TerraformMirrorIdentity,
  contract: ReviewedTerraformContract,
): string {
  const stateBucketName = contract.stateBucketName ?? `${identity.name}-tfstate`;
  const githubRepo = contract.githubRepo ?? identity.name;
  return [
    simpleVariable(
      "project_id",
      "Google Cloud project ID.",
      "string",
      JSON.stringify(identity.projectId),
    ),
    simpleVariable("region", "Primary Google Cloud region.", "string", '"us-east4"'),
    simpleVariable(
      "state_bucket_name",
      "Globally unique Cloud Storage bucket for routine production Terraform state.",
      "string",
      JSON.stringify(stateBucketName),
    ),
    [
      'variable "bootstrap_state_bucket_name" {',
      'description = "Globally unique, separately protected bucket for privileged bootstrap Terraform state."',
      "type = string",
      `default = ${JSON.stringify(`${stateBucketName}-bootstrap`)}`,
      "validation {",
      "condition = var.bootstrap_state_bucket_name != var.state_bucket_name",
      'error_message = "bootstrap_state_bucket_name must be distinct from the routine production state bucket."',
      "}",
      "}",
    ].join("\n"),
    simpleVariable(
      "state_bucket_location",
      "Cloud Storage location for Terraform state.",
      "string",
      '"US-EAST4"',
    ),
    simpleVariable("github_owner", "GitHub repository owner.", "string", '"collinbentley1"'),
    simpleVariable(
      "github_repo",
      "GitHub repository name.",
      "string",
      JSON.stringify(githubRepo),
    ),
    numericIdVariable(
      "github_repository_id",
      "Immutable numeric GitHub repository ID.",
      identity.githubRepositoryId,
    ),
    simpleVariable(
      "manage_automatic_default_service_account_grants_policy",
      "Explicit protected-pipeline decision: true only when the project has an organization parent and the bootstrap identity has organization-level policy authority; false only for a reviewed standalone-project exception.",
      "bool",
    ),
  ].join("\n\n");
}

function simpleVariable(
  name: string,
  description: string,
  type: string,
  defaultExpression?: string,
): string {
  const lines = [
    `variable ${JSON.stringify(name)} {`,
    `description = ${JSON.stringify(description)}`,
    `type = ${type}`,
  ];
  if (defaultExpression !== undefined) lines.push(`default = ${defaultExpression}`);
  lines.push("}");
  return lines.join("\n");
}

function numericIdVariable(name: string, description: string, value: string): string {
  return [
    `variable ${JSON.stringify(name)} {`,
    `description = ${JSON.stringify(description)}`,
    "type = string",
    `default = ${JSON.stringify(value)}`,
    "validation {",
    `condition = can(regex("^[1-9][0-9]*$", var.${name}))`,
    `error_message = ${JSON.stringify(`${name} must be a positive decimal ID.`)}`,
    "}",
    "}",
  ].join("\n");
}

function renderBootstrapOutputs(): string {
  return [
    outputBlock(
      "state_bucket_name",
      "Routine production Terraform state bucket.",
      "module.bootstrap.state_bucket_name",
    ),
    outputBlock(
      "bootstrap_state_bucket_name",
      "Separately protected privileged bootstrap Terraform state bucket.",
      "module.bootstrap.bootstrap_state_bucket_name",
    ),
    outputBlock(
      "workload_identity_provider",
      "Full Workload Identity Provider resource name for GitHub Actions.",
      "module.bootstrap.workload_identity_provider",
    ),
    outputBlock(
      "terraform_service_account_email",
      "Metadata-only service account used by the immutable Terraform convergence workflow.",
      "module.bootstrap.terraform_service_account_email",
    ),
    outputBlock(
      "prod_deploy_service_account_email",
      "Cloud Run deploy service account with read-only access to the exact production image repository and only declared exact-secret version-add grants.",
      "module.bootstrap.prod_deploy_service_account_email",
    ),
    outputBlock(
      "prod_publisher_service_account_email",
      "Artifact Registry-only service account used by the production publish job.",
      "module.bootstrap.prod_publisher_service_account_email",
    ),
    outputBlock(
      "preview_deploy_service_account_email",
      "Cloud Run deploy service account with read-only access to the exact preview image repository.",
      "module.bootstrap.preview_deploy_service_account_email",
    ),
    outputBlock(
      "preview_commit_service_account_email",
      "Exact-workflow transaction identity scoped to preview traffic and exposure changes only.",
      "module.bootstrap.preview_commit_service_account_email",
    ),
    outputBlock(
      "preview_iam_audit_service_account_email",
      "Exact-workflow, read-only cross-project preview runtime IAM auditor.",
      "module.bootstrap.preview_iam_audit_service_account_email",
    ),
    previewOperatorOutput(),
    outputBlock(
      "preview_publisher_service_account_email",
      "Artifact Registry-only service account used by the preview publish job.",
      "module.bootstrap.preview_publisher_service_account_email",
    ),
    outputBlock(
      "deployment_parity_reader_service_account_email",
      "Read-only identity used by exact deployment workflows for DHI parity checks.",
      "module.bootstrap.deployment_parity_reader_service_account_email",
    ),
    outputBlock(
      "runtime_service_account_email",
      "Cloud Run runtime service account.",
      "module.bootstrap.runtime_service_account_email",
    ),
  ].join("\n\n");
}

function renderProductionOutputs(): string {
  return [
    outputBlock(
      "artifact_registry_repository",
      "Artifact Registry Docker repository.",
      "module.site.artifact_registry_repository",
    ),
    outputBlock(
      "cloud_run_service_name",
      "Production Cloud Run service name.",
      "module.site.cloud_run_service_name",
    ),
    outputBlock(
      "cloud_run_service_uri",
      "Production Cloud Run service URL.",
      "module.site.cloud_run_service_uri",
    ),
  ].join("\n\n");
}

function outputBlock(name: string, description: string, value: string): string {
  return [
    `output ${JSON.stringify(name)} {`,
    `description = ${JSON.stringify(description)}`,
    `value = ${value}`,
    "}",
  ].join("\n");
}

function renderBootstrapVersions(
  identity: TerraformMirrorIdentity,
  contract: ReviewedTerraformContract,
): string {
  return renderVersions(identity, contract, true);
}

function renderProductionVersions(
  identity: TerraformMirrorIdentity,
  contract: ReviewedTerraformContract,
): string {
  return renderVersions(identity, contract, false);
}

function renderVersions(
  identity: TerraformMirrorIdentity,
  contract: ReviewedTerraformContract,
  bootstrap: boolean,
): string {
  const stateBucketName = contract.stateBucketName ?? `${identity.name}-tfstate`;
  const lines = [
    "terraform {",
    'required_version = "~> 1.14.0"',
    'backend "gcs" {',
    `bucket = ${JSON.stringify(bootstrap ? `${stateBucketName}-bootstrap` : stateBucketName)}`,
    `prefix = ${JSON.stringify(`${identity.name}/${bootstrap ? "bootstrap" : "prod"}`)}`,
    "}",
    "required_providers {",
    "google = {",
    'source = "hashicorp/google"',
    'version = "= 7.45.0"',
    "}",
    "}",
    "}",
    'provider "google" {',
    "project = var.project_id",
    "region = var.region",
    "}",
  ];
  if (!bootstrap) {
    lines.push(
      'provider "google" {',
      'alias = "no_attribution"',
      "project = var.project_id",
      "region = var.region",
      "add_terraform_attribution_label = false",
      "}",
    );
  }
  return lines.join("\n");
}

function previewIngressVariable(expected: string): string {
  return [
    'variable "preview_ingress" {',
    'description = "Ingress policy for the shared preview Cloud Run service."',
    "type = string",
    "default = " + JSON.stringify(expected),
    "validation {",
    "condition = contains([",
    '"INGRESS_TRAFFIC_ALL",',
    '"INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",',
    "], var.preview_ingress)",
    'error_message = "preview_ingress must allow all traffic or only internal and Cloud Load Balancing traffic."',
    "}",
    "}",
  ].join("\n");
}

function secretSetVariable(name: string, values: readonly string[]): string {
  const description =
    name === "runtime_secret_ids"
      ? "Secret Manager secret containers retained by the platform; does not grant runtime access."
      : name === "runtime_secret_accessor_ids"
        ? "Declared runtime secret IDs whose payloads the production runtime may read."
        : "Declared runtime secret IDs to which the production deploy identity may add immutable versions.";
  const lines = [
    'variable "' + name + '" {',
    "description = " + JSON.stringify(description),
    "type = set(string)",
    "default = " + renderStringList(values),
  ];
  if (name !== "runtime_secret_ids") {
    lines.push(
      "validation {",
      "condition = length(setsubtract(var." + name + ", var.runtime_secret_ids)) == 0",
      'error_message = "' + name + ' must be a subset of runtime_secret_ids."',
      "}",
    );
  }
  lines.push("}");
  return lines.join("\n");
}

function previewOperatorVariable(projectId: string): string {
  return [
    'variable "preview_operator_service_account_email" {',
    "description = " + JSON.stringify(previewOperatorVariableDescription),
    "type = string",
    'default = "gha-preview-operator@' + projectId + '.iam.gserviceaccount.com"',
    "}",
  ].join("\n");
}

function previewOperatorOutput(): string {
  return [
    'output "preview_operator_service_account_email" {',
    "description = " + JSON.stringify(previewOperatorOutputDescription),
    "value = module.bootstrap.preview_operator_service_account_email",
    "}",
  ].join("\n");
}

function renderStringList(values: readonly string[]): string {
  if (values.length === 0) return "[]";
  return "[\n" + values.map((value) => JSON.stringify(value) + ",").join("\n") + "\n]";
}

function skipHorizontalWhitespace(source: string, start: number): number {
  let index = start;
  while (source[index] === " " || source[index] === "\t") index += 1;
  return index;
}

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}
