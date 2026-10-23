#!/usr/bin/env bash
# Install the package into a scratch consumer project, import every public
# entry point and run the CLI. $1 is a packed tarball (CI) or a registry spec
# such as @alphabros/enterprise@1.2.3 (post-release smoke).
set -euo pipefail
spec="$1"
repo="$(cd "$(dirname "$0")/../.." && pwd)"
case "$spec" in *.tgz) spec="$(cd "$(dirname "$spec")" && pwd)/$(basename "$spec")" ;; esac
scratch="$(mktemp -d)"
cd "$scratch"
npm init -y >/dev/null
npm pkg set type=module
# Every peer (optional ones back /schema and /portal) at the ranges this
# checkout declares; happy-dom gives the portal entry a DOM. No lockfile: this
# resolves the way a consumer would.
peers="$(node -e '
  const p = require(process.argv[1]);
  console.log(Object.entries(p.peerDependencies).map(([n, r]) => `${n}@${r}`).join("\n"));
' "$repo/package.json")"
mapfile -t peer_args <<<"$peers"
npm install --no-audit --no-fund "$spec" "${peer_args[@]}" "happy-dom@$(node -p "require('$repo/package.json').devDependencies['happy-dom']")"
cp "$repo/.github/scripts/consumer-smoke.mjs" ./smoke.mjs
node smoke.mjs
npx --no-install ab-enterprise --help
