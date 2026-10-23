// Pack allow-list: the published tarball must contain exactly the package
// surface. A new top-level file or an unexpected dist/ entry fails CI so a
// leaked source map, test fixture or secret never reaches npm unnoticed.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

export const allowed = [
  /^package\.json$/,
  /^README\.md$/,
  /^LICENSE$/,
  /^dist\/(server|schema|client|portal|cli)\/index\.(js|d\.ts)$/,
  // tsup's shared chunks (hashed names), JavaScript or declarations only.
  /^dist\/[\w-]+\.(js|d\.ts)$/,
  /^sql\/\d{4}_[a-z0-9_]+\.sql$/,
];

export const required = [
  "package.json",
  "README.md",
  "LICENSE",
  "sql/0001_enterprise.sql",
  ...["server", "schema", "client", "portal", "cli"].flatMap((entry) => [
    `dist/${entry}/index.js`,
    `dist/${entry}/index.d.ts`,
  ]),
];

export function checkPackFiles(files) {
  const errors = [];
  for (const file of files)
    if (!allowed.some((pattern) => pattern.test(file))) errors.push(`not allow-listed: ${file}`);
  for (const file of required) if (!files.includes(file)) errors.push(`missing: ${file}`);
  if (errors.length) throw new Error(`Pack file list rejected:\n${errors.join("\n")}`);
}

// Usage: tar -tzf package.tgz | node .github/scripts/pack-files.mjs
if (import.meta.url === pathToFileURL(process.argv[1]).href) {
  const files = readFileSync(0, "utf8")
    .split("\n")
    .filter(Boolean)
    .map((line) => line.replace(/^package\//, ""));
  checkPackFiles(files);
  console.log(`Pack file list OK (${files.length} files)`);
}
