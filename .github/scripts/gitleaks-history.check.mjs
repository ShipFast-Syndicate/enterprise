import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

test("Gitleaks catches deleted history at the previously allowlisted path in a different commit", () => {
  const root = mkdtempSync(join(tmpdir(), "enterprise-history-check-"));
  const repository = join(root, "repository");
  mkdirSync(repository);
  const git = (...args) => {
    const result = spawnSync("git", args, { cwd: repository, encoding: "utf8" });
    assert.equal(result.status, 0, "fixture Git operation must succeed");
  };
  try {
    git("init", "--quiet");
    git("config", "user.name", "CI fixture");
    git("config", "user.email", "ci@example.invalid");
    const original = readFileSync(new URL("../../.gitleaks.toml", import.meta.url), "utf8");
    const config = join(root, "gitleaks.toml");
    // A harmless deterministic marker exercises history traversal and the real
    // allowlist. It is neither a credential nor a scanner-exclusion fixture.
    writeFileSync(
      config,
      original +
        '\n[[rules]]\nid = "ci-history-marker"\ndescription = "Harmless history fixture"\nregex = "CI_HISTORY_MARKER_1234567890"\n',
    );
    const directory = join(repository, "test/helpers/fixtures");
    mkdirSync(directory, { recursive: true });
    const file = join(directory, "saml-keys.ts");
    writeFileSync(file, "// CI_HISTORY_MARKER_1234567890\n");
    git("add", ".");
    git("commit", "--quiet", "-m", "Add harmless marker");
    rmSync(file);
    git("add", "--all");
    git("commit", "--quiet", "-m", "Delete marker");
    const report = join(root, "findings.json");
    const result = spawnSync(
      process.env.GITLEAKS_BINARY,
      [
        "git",
        "--redact",
        "--no-banner",
        "--config",
        config,
        "--report-format",
        "json",
        "--report-path",
        report,
        "--exit-code",
        "1",
        repository,
      ],
      { encoding: "utf8" },
    );
    assert.equal(result.status, 1, "the history-only finding must fail");
    const findings = JSON.parse(readFileSync(report, "utf8"));
    assert.ok(
      findings.some(
        (finding) =>
          finding.RuleID === "ci-history-marker" &&
          finding.File === "test/helpers/fixtures/saml-keys.ts",
      ),
    );
  } finally {
    rmSync(root, { recursive: true, force: true });
  }
});
