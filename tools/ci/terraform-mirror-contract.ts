export type TerraformMirrorIdentity = {
  readonly githubRepositoryId: string;
  readonly name?: string | undefined;
  readonly projectId: string;
  readonly serviceName?: string | undefined;
};

export type TerraformMirrorSources = {
  readonly bootstrapMain: string;
  readonly bootstrapOutputs: string;
  readonly productionMain: string;
  readonly productionVariables: string;
};

type ReviewedTerraformContract = {
  readonly name?: string;
  readonly previewIngress: "INGRESS_TRAFFIC_ALL" | "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER";
  readonly projectId?: string;
  readonly requiredServicesOverride: readonly string[] | null;
  readonly runtimeSecretAccessorIds: readonly string[];
  readonly runtimeSecretIds: readonly string[];
  readonly runtimeSecretVersionAdderIds: readonly string[];
  readonly serviceName?: string;
};

const defaultContract: ReviewedTerraformContract = {
  previewIngress: "INGRESS_TRAFFIC_ALL",
  requiredServicesOverride: null,
  runtimeSecretAccessorIds: [],
  runtimeSecretIds: [],
  runtimeSecretVersionAdderIds: [],
};

const reviewedContracts: Readonly<Record<string, ReviewedTerraformContract>> = {
  "1255553151": {
    ...defaultContract,
    name: "cdbentley",
    projectId: "cdbentley",
    serviceName: "cdbentley",
  },
  "1025243085": {
    name: "medlock",
    previewIngress: "INGRESS_TRAFFIC_ALL",
    projectId: "medlock-1025243085",
    requiredServicesOverride: [
      "artifactregistry.googleapis.com",
      "cloudresourcemanager.googleapis.com",
      "firestore.googleapis.com",
      "iam.googleapis.com",
      "iamcredentials.googleapis.com",
      "orgpolicy.googleapis.com",
      "run.googleapis.com",
      "secretmanager.googleapis.com",
      "serviceusage.googleapis.com",
      "storage.googleapis.com",
      "sts.googleapis.com",
    ],
    runtimeSecretAccessorIds: ["waitlist-identity-keyset"],
    runtimeSecretIds: ["waitlist-identity-keyset"],
    runtimeSecretVersionAdderIds: ["waitlist-identity-keyset"],
    serviceName: "medlock",
  },
  "711292980": {
    name: "runsetta",
    previewIngress: "INGRESS_TRAFFIC_ALL",
    projectId: "runsetta",
    requiredServicesOverride: [
      "artifactregistry.googleapis.com",
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
    runtimeSecretIds: [
      "openai-api-key",
      "spotify-client-id",
      "spotify-client-secret",
      "spotify-redirect-uri",
    ],
    runtimeSecretVersionAdderIds: [],
    serviceName: "runsetta",
  },
  "280932482": {
    ...defaultContract,
    name: "critical-history",
    previewIngress: "INGRESS_TRAFFIC_INTERNAL_LOAD_BALANCER",
    projectId: "critical-history-16823277",
    serviceName: "critical-history",
  },
};

const previewOperatorVariableDescription =
  "Deprecated transition-only preview operator email retained for input compatibility; receives no IAM grant.";
const previewOperatorOutputDescription =
  "Retired transition-only preview operator service account; receives no steady-state operational grants.";

export function validateTerraformMirrorContract(
  identity: TerraformMirrorIdentity,
  sources: TerraformMirrorSources,
): string[] {
  const failures: string[] = [];
  const contract = reviewedContracts[identity.githubRepositoryId] ?? defaultContract;

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
    productionMain: parseDocument("infra/terraform/prod/main.tf", sources.productionMain, failures),
    productionVariables: parseDocument(
      "infra/terraform/prod/variables.tf",
      sources.productionVariables,
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
  if (productionModule) {
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
    "preview_operator_service_account_email",
    previewOperatorVariable(identity.projectId),
    "infra/terraform/prod/variables.tf preview operator input must retain the retired no-grant semantics",
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
