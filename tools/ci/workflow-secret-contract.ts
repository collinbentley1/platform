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
    if (containsSecretContextReference(value)) {
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
    if (/^secrets$/i.test(key) || containsSecretContextReference(key)) {
      references.push({ job: jobFor(path), path: [...path, `<key:${key}>`].join("."), value: key });
    }
    visit(item, [...path, key], nestedAncestors, references);
  }
}

function containsSecretContextReference(value: string): boolean {
  let offset = 0;
  while (offset < value.length) {
    const start = value.indexOf("${{", offset);
    if (start < 0) {
      return false;
    }

    let quote: "'" | '"' | undefined;
    let index = start + 3;
    for (; index < value.length - 1; index += 1) {
      const character = value[index];
      if (quote) {
        if (character === quote) {
          if (quote === "'" && value[index + 1] === "'") {
            index += 1;
          } else {
            quote = undefined;
          }
        } else if (quote === '"' && character === "\\") {
          index += 1;
        }
        continue;
      }
      if (character === "'" || character === '"') {
        quote = character;
        continue;
      }
      if (character === "}" && value[index + 1] === "}") {
        const expression = value.slice(start, index + 2);
        if (secretContextToken.test(expression)) {
          return true;
        }
        offset = index + 2;
        break;
      }
    }
    if (index >= value.length - 1) {
      return secretContextToken.test(value.slice(start));
    }
  }
  return false;
}

function jobFor(path: Array<number | string>): string | null {
  return path[0] === "jobs" && typeof path[1] === "string" ? path[1] : null;
}
