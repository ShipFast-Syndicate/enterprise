import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { createVitest } from "vitest/node";
import { parse } from "yaml";
import {
  checkBase,
  checkRelease,
  checkReleaseStatus,
  checkSarif,
  checkSummary,
  checkTrivy,
  requiredJobs,
} from "./ci-policy.mjs";

const head = "a".repeat(40);

test("Vitest projects inherit the declared timeout and cover executable source", async () => {
  const context = await createVitest("test", { watch: false });
  try {
    assert.deepEqual(
      context.projects.map((project) => ({
        name: project.name,
        timeout: project.config.testTimeout,
        environment: project.config.environment,
      })),
      [
        { name: "server", timeout: 20000, environment: "node" },
        { name: "portal", timeout: 20000, environment: "happy-dom" },
      ],
    );
    assert.deepEqual(context.config.coverage.include, ["src/**"]);
    // The resolved provider also appends its own test/config exclusions.
    assert.deepEqual(context.vite.config.test.coverage.exclude, ["**/*.sql", "**/*.md"]);
  } finally {
    await context.close();
  }
});
const event = { eventName: "pull_request", author: "contributor", base: "main" };
const success = () => Object.fromEntries(requiredJobs.map((job) => [job, { result: "success" }]));
const status = (context, state = "success", id = 1, updated_at = "2026-09-19T12:00:00Z") => ({
  context,
  state,
  id,
  updated_at,
});
const ready = () => ({
  sha: head,
  statuses: [status("deploy-qa/runner"), status("deploy-qa/browser")],
});

test("GitFlow accepts existing branch policy and rejects wrong directions", () => {
  for (const branch of ["develop", "release/1", "hotfix/fix"])
    assert.equal(checkBase("main", branch), "pass");
  for (const branch of ["fix/test", "feature", "develop-evil", "$(touch sentinel)"])
    assert.throws(() => checkBase("main", branch));
  assert.throws(() => checkBase("develop", "main"));
  assert.equal(checkBase("develop", "fix/example"), "pass");
  assert.equal(checkBase("develop", "unconventional"), "warning");
});

test("every required gate blocks failure, cancellation, missing result and unexpected skip", () => {
  checkSummary(success(), event);
  for (const job of requiredJobs) {
    for (const result of ["failure", "cancelled", "skipped", undefined]) {
      const needs = success();
      needs[job] = { result };
      assert.throws(() => checkSummary(needs, event), undefined, `${job}: ${result}`);
    }
    const needs = success();
    delete needs[job];
    assert.throws(() => checkSummary(needs, event));
  }
});

test("only documented event skips are accepted", () => {
  const needs = success();
  needs.base.result = "skipped";
  needs.release.result = "skipped";
  for (const eventName of ["push", "workflow_dispatch"]) checkSummary(needs, { eventName });
  needs.node.result = "skipped";
  assert.throws(() => checkSummary(needs, { eventName: "push", author: "dependabot[bot]" }));
  needs.base.result = "success";
  checkSummary(needs, { eventName: "pull_request", author: "dependabot[bot]", base: "develop" });
  assert.throws(() => checkSummary(needs, { ...event, base: "develop" }));
  needs.audit.result = "skipped";
  assert.throws(() =>
    checkSummary(needs, { eventName: "pull_request", author: "dependabot[bot]", base: "develop" }),
  );
});

test("release requires both current exact-head QA states, never an old success", () => {
  checkReleaseStatus(ready(), head);
  for (const state of ["failure", "error", "pending", "cancelled", undefined]) {
    const document = ready();
    document.statuses[0].state = state;
    assert.throws(() => checkReleaseStatus(document, head));
  }
  assert.throws(() => checkReleaseStatus({ ...ready(), sha: "b".repeat(40) }, head));
  assert.throws(() => checkReleaseStatus({ sha: head, statuses: [] }, head));
  assert.throws(() => checkReleaseStatus({ ...ready(), statuses: {} }, head));
  const document = ready();
  const failed = status("deploy-qa/runner", "failure", 2, "2026-09-19T13:00:00Z");
  for (const statuses of [
    [...document.statuses, failed],
    [failed, ...document.statuses],
  ]) {
    assert.throws(() => checkReleaseStatus({ sha: head, statuses }, head));
  }
});

test("release fetch is GET-only and fails closed on HTTP, JSON, network and head-race errors", async () => {
  const requests = [];
  const options = { repository: "example/public", number: "8", head, token: "fixture-token" };
  const fetchImpl = async (url, config) => {
    requests.push({ url, config });
    return {
      ok: true,
      json: async () => (url.includes("/pulls/") ? { head: { sha: head }, labels: [] } : ready()),
    };
  };
  await checkRelease({ ...options, fetchImpl });
  assert.equal(requests.length, 2);
  for (const request of requests) {
    assert.equal(request.config.method, undefined); // fetch defaults to GET
    assert.equal(request.config.redirect, "error");
    assert.match(request.url, /^https:\/\/api\.github\.com\/repos\/example\/public\//);
  }
  for (const code of [401, 403, 404, 429, 500]) {
    await assert.rejects(
      checkRelease({ ...options, fetchImpl: async () => ({ ok: false, status: code }) }),
    );
  }
  await assert.rejects(
    checkRelease({
      ...options,
      fetchImpl: async () => ({
        ok: true,
        json: async () => {
          throw new Error("Invalid JSON");
        },
      }),
    }),
  );
  await assert.rejects(
    checkRelease({
      ...options,
      fetchImpl: async () => {
        throw new Error("Network failure");
      },
    }),
  );
  await assert.rejects(
    checkRelease({
      ...options,
      fetchImpl: async () => ({
        ok: true,
        json: async () => ({ head: { sha: "b".repeat(40) }, labels: [{ name: "release_grant" }] }),
      }),
    }),
  );
});

test("live release_grant overrides QA only for the matching PR head", async () => {
  let calls = 0;
  await checkRelease({
    repository: "example/public",
    number: "8",
    head,
    token: "fixture-token",
    fetchImpl: async () => {
      calls++;
      return {
        ok: true,
        json: async () => ({ head: { sha: head }, labels: [{ name: "release_grant" }] }),
      };
    },
  });
  assert.equal(calls, 1);
});

test("scanner reports cannot convert malformed, absent or failing evidence to success", () => {
  const sarif = { version: "2.1.0", runs: [{ results: [] }] };
  checkSarif(sarif);
  for (const report of [
    {},
    { runs: [] },
    { version: "2.1.0", runs: [] },
    { version: "2.1.0", runs: [{}] },
    { version: "2.1.0", runs: [{ results: [{}] }] },
    { version: "2.1.0", runs: [{ results: [], invocations: [{ executionSuccessful: false }] }] },
  ])
    assert.throws(() => checkSarif(report));
  checkTrivy({
    SchemaVersion: 2,
    Results: [
      {
        Target: "fixture",
        Vulnerabilities: [{ Severity: "LOW" }],
        Misconfigurations: [{ Severity: "HIGH", Status: "PASS" }],
      },
    ],
  });
  for (const field of ["Vulnerabilities", "Secrets", "Misconfigurations"]) {
    assert.throws(() =>
      checkTrivy({
        SchemaVersion: 2,
        Results: [{ Target: "fixture", [field]: [{ Severity: "HIGH", Status: "FAIL" }] }],
      }),
    );
    assert.throws(() =>
      checkTrivy({ SchemaVersion: 2, Results: [{ Target: "fixture", [field]: {} }] }),
    );
  }
  for (const report of [
    {},
    { SchemaVersion: 2 },
    { SchemaVersion: 2, Results: [{}] },
    { SchemaVersion: 2, Results: [{ Target: "fixture", Secrets: [{}] }] },
    { SchemaVersion: 2, Results: [{ Target: "fixture", Secrets: [{ Severity: "misspelled" }] }] },
    {
      SchemaVersion: 2,
      Results: [{ Target: "fixture", Misconfigurations: [{ Severity: "HIGH" }] }],
    },
  ])
    assert.throws(() => checkTrivy(report));
});

const caller = parse(readFileSync(new URL("../workflows/ci.yml", import.meta.url), "utf8"));
const workflow = parse(
  readFileSync(new URL("../workflows/public-ci.yml", import.meta.url), "utf8"),
);
const publicActions = new Set([
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
  "actions/setup-node@820762786026740c76f36085b0efc47a31fe5020",
  "pnpm/action-setup@0ebf47130e4866e96fce0953f49152a61190b271",
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a",
  "actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97",
]);

function assertClosure(caller, workflow) {
  assert.deepEqual(Object.keys(caller.on).sort(), ["pull_request", "push", "workflow_dispatch"]);
  assert.equal(caller.jobs.ci.uses, "./.github/workflows/public-ci.yml");
  assert.equal(caller.jobs.ci.secrets, undefined);
  assert.deepEqual(workflow.on, { workflow_call: null });
  assert.deepEqual(Object.keys(workflow.jobs).sort(), [...requiredJobs, "summary"].sort());
  assert.deepEqual([...workflow.jobs.summary.needs].sort(), [...requiredJobs].sort());
  assert.equal(workflow.jobs.summary.name, undefined);
  assert.equal(workflow.jobs.summary.if, "always()");
  for (const configuration of [caller, workflow, ...Object.values(workflow.jobs)]) {
    for (const permission of Object.values(configuration.permissions ?? {}))
      assert.equal(permission, "read");
  }
  assert.equal(
    workflow.jobs.node.if,
    "github.event_name != 'pull_request' || github.event.pull_request.user.login != 'dependabot[bot]'",
  );
  assert.equal(workflow.jobs.base.if, "github.event_name == 'pull_request'");
  assert.equal(
    workflow.jobs.release.if,
    "github.event_name == 'pull_request' && github.base_ref == 'main'",
  );
  for (const [name, job] of Object.entries(workflow.jobs)) {
    assert.equal(job["runs-on"], "ubuntu-latest");
    assert.equal(job.uses, undefined);
    assert.equal(job["continue-on-error"], undefined);
    if (!["node", "base", "release", "summary"].includes(name)) assert.equal(job.if, undefined);
    for (const step of job.steps) {
      assert.equal(step["continue-on-error"], undefined);
      if (step.uses) assert.ok(publicActions.has(step.uses), `Unverified action: ${step.uses}`);
      if (step.uses?.startsWith("actions/checkout@"))
        assert.equal(step.with["persist-credentials"], false);
      if (step.run)
        assert.doesNotMatch(
          step.run,
          /\$\{\{|secrets\.|gh\s+(pr|issue)\s+(comment|edit)|curl[^\n]*(-X\s+(POST|PUT|PATCH|DELETE))/,
        );
    }
  }
  const fullHistory = workflow.jobs.gitleaks.steps.find((step) =>
    step.uses?.startsWith("actions/checkout@"),
  );
  assert.equal(fullHistory.with["fetch-depth"], 0);
  for (const command of ["pnpm lint", "pnpm typecheck", "pnpm format:check", "pnpm test:coverage"])
    assert.ok(workflow.jobs.node.steps.some((step) => step.run === command));
  assert.ok(workflow.jobs.build.steps.some((step) => step.run === "pnpm build"));
  assert.ok(workflow.jobs.audit.steps.some((step) => step.run === "pnpm audit --audit-level=high"));
  assert.ok(
    workflow.jobs.contracts.steps.some(
      (step) => step.run === "node --test .github/scripts/*.test.mjs",
    ),
  );
  const scripts = (job) => workflow.jobs[job].steps.map((step) => step.run ?? "").join("\n");
  const semgrep = scripts("semgrep");
  for (const rules of [
    "p/default",
    "p/typescript",
    "p/javascript",
    "p/security-audit",
    "p/secrets",
    "p/owasp-top-ten",
  ])
    assert.ok(semgrep.includes(`--config=${rules}`));
  assert.match(semgrep, /--strict --error/);
  assert.match(semgrep, /if \[ "\$status" -ne 0 \]; then exit "\$status"; fi/);
  assert.match(semgrep, /ci-policy\.mjs sarif/);
  const trivy = scripts("trivy");
  assert.match(trivy, /--scanners vuln,secret,misconfig --severity CRITICAL,HIGH/);
  assert.match(trivy, /--ignore-unfixed/);
  assert.match(trivy, /ci-policy\.mjs trivy/);
  const gitleaks = scripts("gitleaks");
  assert.match(gitleaks, /git --redact --no-banner --config \.gitleaks\.toml/);
  assert.match(gitleaks, /--exit-code 1/);
  assert.match(gitleaks, /ci-policy\.mjs sarif/);
  assert.match(gitleaks, /node --test \.github\/scripts\/gitleaks-history\.check\.mjs/);
}

test("public CI closure preserves gates and never requests private dependencies, writes or persistent runners", () =>
  assertClosure(caller, workflow));

test("closure detects inaccessible reusables, persistent leaves, disabled gates and softened failures", () => {
  const mutations = [
    (c) => {
      c.jobs.ci.uses = "private/hub/.github/workflows/ci.yml@" + head;
    },
    (c, w) => {
      w.jobs.build["runs-on"] = ["self-hosted"];
    },
    (c, w) => {
      w.jobs.audit.if = "false";
    },
    (c, w) => {
      w.jobs.semgrep.steps[0]["continue-on-error"] = true;
    },
    (c, w) => {
      w.jobs.summary.needs.pop();
    },
    (c, w) => {
      w.jobs.semgrep.steps = w.jobs.semgrep.steps.filter((step) => step.name !== "Scan code");
    },
    (c) => {
      c.permissions["pull-requests"] = "write";
    },
    (c, w) => {
      w.jobs.gitleaks.steps[0].with["fetch-depth"] = 1;
    },
  ];
  for (const mutate of mutations) {
    const c = structuredClone(caller),
      w = structuredClone(workflow);
    mutate(c, w);
    assert.throws(() => assertClosure(c, w));
  }
});
