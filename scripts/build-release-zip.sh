#!/usr/bin/env bash
# Builds dist/aiscan-<version>.zip and dist/aiscan-<version>.zip.sha256.
# Used by .github/workflows/release.yml; runnable locally from the repo root:
#   bash scripts/build-release-zip.sh 0.2.0
# The zip holds only what aiscan.ps1 needs at runtime plus the docs that ship
# with it. Tests, samples, docs/, .github and .claude are left out.
set -euo pipefail

version="${1:?usage: build-release-zip.sh <version, e.g. 0.2.0>}"
if ! [[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+(-[0-9A-Za-z.]+)?$ ]]; then
  echo "version must look like 1.2.3 or 1.2.3-rc.1 (no leading v): $version" >&2
  exit 1
fi

# The committed VERSION file is what a checkout without git prints. It has
# to match the release or a tagged zip and a tagged clone disagree.
repo_version=""
if [[ -f VERSION ]]; then
  repo_version="$(head -n 1 VERSION | tr -d '[:space:]')"
fi
if [[ -z "$repo_version" ]]; then
  echo "VERSION file is missing or empty. Set it to $version before releasing." >&2
  exit 1
fi
if [[ "$repo_version" != "$version" ]]; then
  echo "VERSION file says '$repo_version' but this release is '$version'." >&2
  echo "Update VERSION to $version and tag that commit." >&2
  exit 1
fi

name="aiscan-$version"
dist="dist"
stage="$dist/$name"
rm -rf "$stage" "$dist/$name.zip" "$dist/$name.zip.sha256"
mkdir -p "$stage"

files=(aiscan.ps1 paths.example.json README.md LICENSE SECURITY.md SCHEMA.md THIRD_PARTY_NOTICES.md VERSION)
dirs=(components core report scripts tools)

for f in "${files[@]}"; do cp "$f" "$stage/"; done
for d in "${dirs[@]}"; do cp -r "$d" "$stage/"; done

# Drop test suites and Python caches from the copied folders.
find "$stage" -type d \( -name tests -o -name __pycache__ \) -prune -exec rm -rf {} +
find "$stage" -type f -name '*.pyc' -delete

# A release zip has no .git, so this file is what aiscan prints. It matches
# the version checked above.
printf '%s\n' "$version" > "$stage/VERSION"

# Fail if aiscan.ps1's runtime entry points are missing.
for need in core/common.py core/paths.py core/discover.py core/scan_diff.py \
            core/tool_version.py core/run_status.py \
            report/build-briefing.py report/templates/briefing.css; do
  [[ -f "$stage/$need" ]] || { echo "missing from zip: $need" >&2; exit 1; }
done
# Collector scripts named in aiscan.ps1's $ScriptFor map ("claude\claude.py" ...).
grep -oE '= "[a-z-]+\\[a-z-]+\.py"' aiscan.ps1 | sed -e 's/^= "//' -e 's/"$//' | tr '\\' '/' | while read -r rel; do
  [[ -f "$stage/components/$rel" ]] || { echo "missing collector: components/$rel" >&2; exit 1; }
done

(cd "$dist" && TZ=UTC find "$name" -exec touch -t 198001010000 {} + && \
  find "$name" -type f | LC_ALL=C sort | zip -q -X "$name.zip" -@)
(cd "$dist" && sha256sum "$name.zip" > "$name.zip.sha256")

echo "Built $dist/$name.zip"
cat "$dist/$name.zip.sha256"
