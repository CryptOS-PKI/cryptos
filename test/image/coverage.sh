#!/usr/bin/env bash
# Merge the coverage counters the full-image suite collected and report them:
# one directory per VM (copied off its coverage disk by the suite) plus one for
# the coverage-instrumented cryptosctl. Writes, into <out>:
#   coverage.txt          the merged profile (go tool cover format)
#   coverage.html         the HTML report
#   coverage-percent.txt  go tool covdata percent, one line per package
#   coverage-summary.md   the per-package table for the job summary
#
# Usage: test/image/coverage.sh <counter-root> <out>
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
root="$(cd "$here/../.." && pwd)"
counters="${1:?counter root}"
out="${2:?output dir}"

log() { printf '[e2e:image coverage] %s\n' "$*" >&2; }

dirs=()
for d in "$counters"/*/; do
  d="${d%/}"
  if compgen -G "$d/covmeta.*" >/dev/null; then
    dirs+=("$d")
    log "$(basename "$d"): $(find "$d" -name 'covcounters.*' | wc -l) counter file(s)"
  else
    log "$(basename "$d"): no coverage meta-data, left out"
  fi
done
if [ "${#dirs[@]}" -eq 0 ]; then
  log "no coverage data found under $counters"
  printf '## Coverage\n\nNo coverage data came back from the run.\n' >"$out/coverage-summary.md"
  exit 1
fi
inputs="$(IFS=,; echo "${dirs[*]}")"

cd "$root"
go tool covdata percent -i="$inputs" | sort >"$out/coverage-percent.txt"
go tool covdata textfmt -i="$inputs" -o "$out/coverage.txt"
go tool cover -html="$out/coverage.txt" -o "$out/coverage.html"
total="$(go tool cover -func="$out/coverage.txt" | awk '/^total:/ {print $NF}')"

{
  printf '## Coverage\n\n'
  printf 'Statements covered by the booted nodes'"'"' init and the host'"'"'s cryptosctl: **%s** of the packages those binaries link. ' "$total"
  printf 'Sources: %s. The HTML report is in the run'"'"'s artifacts.\n\n' "$(for d in "${dirs[@]}"; do basename "$d"; done | paste -sd, - | sed 's/,/, /g')"
  printf '| Package | Covered |\n|---|---|\n'
  # covdata prints "<import path>  coverage: 12.3% of statements".
  sed -E 's#^[[:space:]]*github.com/CryptOS-PKI/cryptos/##; s#[[:space:]]+coverage: ([0-9.]+)% of statements#|\1#' "$out/coverage-percent.txt" |
    sort -t'|' -k2 -g -r |
    awk -F'|' '{ printf "| `%s` | %s%% |\n", $1, $2 }'
  printf '\n'
} >"$out/coverage-summary.md"
log "total $total; report in $out/coverage.html"
