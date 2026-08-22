const secretContextToken = /(^|[^A-Za-z0-9_-])secrets(?=[^A-Za-z0-9_-]|$)/i;

export interface SecretContextReference {
  job: string | null;
  path: string;
  value: string;
}

export function semanticSecretContextReferences(workflow: string): SecretContextReference[] {
  const parsed: unknown = Bun.YAML.parse(workflow);
  const references: SecretContextReference[] = [];
  visit(parsed, [], new Set<object>(), references);
  return references;
}

function visit(
  value: unknown,
  path: Array<number | string>,
  ancestors: Set<object>,
  references: SecretContextReference[],
): void {
  if (typeof value === "string") {
    if (secretContextToken.test(value)) {
      references.push({ job: jobFor(path), path: path.join("."), value });
    }
    return;
  }
  if (value === null || typeof value !== "object") {
    return;
  }
  if (ancestors.has(value)) {
    throw new Error(`Cyclic YAML alias at ${path.join(".") || "<root>"}.`);
  }

  const nestedAncestors = new Set(ancestors);
  nestedAncestors.add(value);
  if (Array.isArray(value)) {
    value.forEach((item, index) => visit(item, [...path, index], nestedAncestors, references));
    return;
  }

  for (const [key, item] of Object.entries(value)) {
    if (secretContextToken.test(key)) {
      references.push({ job: jobFor(path), path: [...path, `<key:${key}>`].join("."), value: key });
    }
    visit(item, [...path, key], nestedAncestors, references);
  }
}

function jobFor(path: Array<number | string>): string | null {
  return path[0] === "jobs" && typeof path[1] === "string" ? path[1] : null;
}
