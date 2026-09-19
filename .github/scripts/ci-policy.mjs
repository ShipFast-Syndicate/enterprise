import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

class PolicyError extends Error {}

export const requiredJobs = [
  "contracts",
  "node",
  "semgrep",
  "trivy",
  "gitleaks",
  "audit",
  "build",
  "base",
  "release",
];

export function checkBase(base, head) {
  if (base === "main" && !/^(develop|release\/.+|hotfix\/.+)$/.test(head)) {
    throw new PolicyError("Only develop, release/* and hotfix/* may target main");
  }
  if (base === "develop" && head === "main") {
    throw new PolicyError("main must not target develop");
  }
  const conventional =
    /^(feat|fix|chore|docs|refactor|test|ci|build|perf|style|task|hotfix|release|dependabot|renovate|analysis)\/.+/;
  return base === "develop" && !conventional.test(head) ? "warning" : "pass";
}

export function checkSummary(needs, event) {
  for (const job of requiredJobs) {
    const result = needs[job]?.result;
    const deliberateSkip =
      (job === "node" &&
        event.eventName === "pull_request" &&
        event.author === "dependabot[bot]") ||
      (job === "base" && event.eventName !== "pull_request") ||
      (job === "release" && (event.eventName !== "pull_request" || event.base !== "main"));
    if (result !== "success" && !(result === "skipped" && deliberateSkip)) {
      throw new PolicyError(`Required CI gate ${job}: ${result ?? "missing"}`);
    }
  }
}

export function checkReleaseStatus(document, head) {
  if (document.sha !== head || !Array.isArray(document.statuses)) {
    throw new PolicyError("Invalid or wrong-head combined status response");
  }
  for (const context of ["deploy-qa/runner", "deploy-qa/browser"]) {
    const matches = document.statuses.filter((status) => status.context === context);
    if (!matches.length) throw new PolicyError(`Missing ${context}`);
    if (
      matches.some(
        (status) =>
          !Number.isFinite(Date.parse(status.updated_at)) || !Number.isSafeInteger(status.id),
      )
    ) {
      throw new PolicyError(`Invalid ${context} status metadata`);
    }
    matches.sort((a, b) => Date.parse(b.updated_at) - Date.parse(a.updated_at) || b.id - a.id);
    if (matches[0].state !== "success") throw new PolicyError(`${context} is not successful`);
  }
}

export async function checkRelease({ repository, number, head, token, fetchImpl = fetch }) {
  if (
    !/^[A-Za-z0-9_.-]+\/[A-Za-z0-9_.-]+$/.test(repository) ||
    !/^[1-9][0-9]*$/.test(number) ||
    !/^[0-9a-f]{40}$/.test(head)
  ) {
    throw new PolicyError("Invalid release identity");
  }
  const get = async (path) => {
    const response = await fetchImpl(`https://api.github.com/repos/${repository}/${path}`, {
      headers: {
        Accept: "application/vnd.github+json",
        Authorization: `Bearer ${token}`,
        "X-GitHub-Api-Version": "2022-11-28",
      },
      signal: AbortSignal.timeout(30000),
      redirect: "error",
    });
    if (!response.ok) throw new PolicyError(`Release API failed: HTTP ${response.status}`);
    return response.json();
  };
  const pr = await get(`pulls/${number}`);
  if (pr.head?.sha !== head || !Array.isArray(pr.labels))
    throw new PolicyError("PR head changed or response invalid");
  if (pr.labels.some((label) => label.name === "release_grant")) return;
  checkReleaseStatus(await get(`commits/${head}/status?per_page=100`), head);
}

export function checkTrivy(report) {
  if (report.SchemaVersion !== 2 || !Array.isArray(report.Results))
    throw new PolicyError("Invalid Trivy report");
  let findings = 0;
  for (const result of report.Results) {
    if (typeof result.Target !== "string") throw new PolicyError("Missing Trivy target");
    for (const field of ["Vulnerabilities", "Misconfigurations", "Secrets"]) {
      if (result[field] !== undefined && !Array.isArray(result[field]))
        throw new PolicyError("Invalid Trivy findings");
      for (const finding of result[field] ?? []) {
        if (!["UNKNOWN", "LOW", "MEDIUM", "HIGH", "CRITICAL"].includes(finding.Severity))
          throw new PolicyError("Invalid Trivy severity");
        if (
          field === "Misconfigurations" &&
          !["PASS", "FAIL", "EXCEPTION"].includes(finding.Status)
        )
          throw new PolicyError("Invalid Trivy configuration result");
        if (
          ["CRITICAL", "HIGH"].includes(finding.Severity) &&
          (field !== "Misconfigurations" || finding.Status === "FAIL")
        )
          findings++;
      }
    }
  }
  if (findings) throw new PolicyError(`Trivy reported ${findings} CRITICAL/HIGH findings`);
}

export function checkSarif(report) {
  if (report.version !== "2.1.0" || !Array.isArray(report.runs) || !report.runs.length)
    throw new PolicyError("Invalid SARIF report");
  for (const run of report.runs) {
    if (!Array.isArray(run.results)) throw new PolicyError("Missing SARIF results");
    if (run.results.length)
      throw new PolicyError(`Scanner reported ${run.results.length} findings`);
    if (run.invocations?.some((invocation) => invocation.executionSuccessful === false))
      throw new PolicyError("Scanner execution failed");
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  try {
    const operation = process.argv[2];
    if (operation === "base") {
      if (checkBase(process.env.PR_BASE, process.env.PR_HEAD) === "warning")
        console.log("::warning::Use a conventional branch prefix for develop PRs");
    } else if (operation === "release") {
      await checkRelease({
        repository: process.env.GITHUB_REPOSITORY,
        number: process.env.PR_NUMBER,
        head: process.env.PR_SHA,
        token: process.env.GITHUB_TOKEN,
      });
    } else if (operation === "summary") {
      checkSummary(JSON.parse(process.env.CI_NEEDS), {
        eventName: process.env.CI_EVENT,
        author: process.env.PR_AUTHOR,
        base: process.env.PR_BASE,
      });
    } else if (operation === "trivy" || operation === "sarif") {
      (operation === "trivy" ? checkTrivy : checkSarif)(
        JSON.parse(readFileSync(process.argv[3], "utf8")),
      );
    } else throw new PolicyError("Unknown CI policy operation");
    console.log("CI policy passed");
  } catch (error) {
    // Policy errors never include API bodies, headers, tokens or scanner snippets.
    console.error(
      error instanceof PolicyError
        ? error.message
        : "CI policy failed: invalid input or unavailable dependency",
    );
    process.exitCode = 1;
  }
}
