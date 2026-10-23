import assert from "node:assert/strict";
import { test } from "node:test";
import { checkPackFiles, required } from "./pack-files.mjs";

test("pack allow-list accepts the package surface and rejects drift", () => {
  const files = [...required, "dist/plugin-BNrEGuul.d.ts", "sql/0002_scim_1_7.sql"];
  checkPackFiles(files);
  for (const extra of ["dist/server/index.js.map", "src/server/index.ts", ".env", "test/x.ts"])
    assert.throws(() => checkPackFiles([...files, extra]), /not allow-listed/);
  assert.throws(() => checkPackFiles(files.filter((f) => f !== "dist/cli/index.js")), /missing/);
});
