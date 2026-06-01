import { readdir, readFile, writeFile } from "node:fs/promises";
import { join, relative } from "node:path";

const mode = Bun.argv.includes("--write") ? "write" : "check";
const root = join(import.meta.dir, "..");
const formattedRoots = new Set([".github", "docs", "templates", "terraform", "tools"]);
const formattedFiles = new Set([
  ".gitignore",
  "bunfig.toml",
  "package.json",
  "README.md",
  "tsconfig.json",
]);
const includeExtensions = new Set([
  ".json",
  ".md",
  ".tf",
  ".toml",
  ".ts",
  ".yml",
  ".yaml",
]);
const ignoredDirectories = new Set([".git", ".terraform", "node_modules"]);
const changed: string[] = [];

for await (const filePath of walk(root)) {
  const relativePath = relative(root, filePath);
  const topLevel = relativePath.split("/")[0] ?? "";

  if (!formattedFiles.has(relativePath) && !formattedRoots.has(topLevel)) {
    continue;
  }

  const extension = getExtension(filePath);
  if (!includeExtensions.has(extension)) {
    continue;
  }

  const original = await readFile(filePath, "utf8");
  const formatted = `${original.replace(/\r\n/g, "\n").replace(/[ \t]+$/gm, "").trimEnd()}\n`;

  if (original !== formatted) {
    changed.push(relativePath);
    if (mode === "write") {
      await writeFile(filePath, formatted);
    }
  }
}

if (changed.length > 0 && mode === "check") {
  console.error(`Formatting drift:\n${changed.map((file) => `- ${file}`).join("\n")}`);
  process.exit(1);
}

function getExtension(path: string): string {
  const name = path.split("/").at(-1) ?? "";
  return name.includes(".") ? `.${name.split(".").at(-1)}` : "";
}

async function* walk(directory: string): AsyncGenerator<string> {
  const entries = await readdir(directory, { withFileTypes: true });

  for (const entry of entries) {
    if (entry.isDirectory()) {
      if (!ignoredDirectories.has(entry.name)) {
        yield* walk(join(directory, entry.name));
      }
    } else if (entry.isFile()) {
      yield join(directory, entry.name);
    }
  }
}
