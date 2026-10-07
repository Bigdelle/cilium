#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright Authors of Cilium
#
# Run the offline memloop memory scenarios (see test/memloop/README.md).
#
# Usage:
#   test/memloop/run-offline-scenarios.sh [SCENARIO_FILTER]
#
#   SCENARIO_FILTER  optional extended regex matched against the scenario
#                    "name" in scenarios.json (e.g. 'dns', '^cidr-policy',
#                    'inuse$'). Default: all scenarios.
#
# Environment:
#   BENCHTIME   go test -benchtime value (default: 1x)
#   COUNT       go test -count value (default: 1)
#   OUT         output directory (default: /tmp/memloop-offline)
#   MEMPROFILE  if set to 1, also write <OUT>/<name>.memprofile (and keep the
#               test binary as <OUT>/<name>.test for pprof)
#   GO          go binary to use (default: go)
#   GOFLAGS_EXTRA extra flags passed to go test (default: empty)
#
# Outputs (in $OUT):
#   <name>.txt     raw `go test -bench` output per scenario
#   results.txt    concatenated benchmark lines of all scenarios
#   summary.tsv    name, benchmark, ns/op, B/op, allocs/op, inuse-B/op
#                  (one line per benchmark result line)

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
SCENARIOS_JSON="${SCRIPT_DIR}/scenarios.json"

FILTER="${1:-.}"
BENCHTIME="${BENCHTIME:-1x}"
COUNT="${COUNT:-1}"
OUT="${OUT:-/tmp/memloop-offline}"
MEMPROFILE="${MEMPROFILE:-0}"
GO="${GO:-go}"
GOFLAGS_EXTRA="${GOFLAGS_EXTRA:-}"

mkdir -p "${OUT}"
: > "${OUT}/results.txt"
printf 'name\tbenchmark\tns_per_op\tB_per_op\tallocs_per_op\tinuse_B_per_op\n' > "${OUT}/summary.tsv"

# Emit "name<TAB>package<TAB>bench_regex" for every scenario matching FILTER.
list_scenarios() {
	if command -v jq >/dev/null 2>&1; then
		jq -r '.[] | [.name, .package, .bench_regex] | @tsv' "${SCENARIOS_JSON}"
	else
		python3 -c '
import json, sys
for s in json.load(open(sys.argv[1])):
    print("\t".join([s["name"], s["package"], s["bench_regex"]]))
' "${SCENARIOS_JSON}"
	fi
}

mapfile -t SCENARIOS < <(list_scenarios | awk -F'\t' -v f="${FILTER}" '$1 ~ f')
if [[ ${#SCENARIOS[@]} -eq 0 ]]; then
	echo "no scenario matches filter '${FILTER}'" >&2
	exit 1
fi

cd "${REPO_ROOT}"

failed=()
for line in "${SCENARIOS[@]}"; do
	IFS=$'\t' read -r name pkg regex <<<"${line}"
	echo "==> ${name}: ${pkg} -bench='${regex}' -benchtime=${BENCHTIME} -count=${COUNT}"

	args=(test "${pkg}" -run='^$' -bench="${regex}" -benchtime="${BENCHTIME}"
		-count="${COUNT}" -benchmem -timeout=30m)
	if [[ "${MEMPROFILE}" == "1" ]]; then
		args+=(-memprofile="${OUT}/${name}.memprofile" -o "${OUT}/${name}.test")
	fi
	# shellcheck disable=SC2206
	extra=(${GOFLAGS_EXTRA})

	if ! "${GO}" "${args[@]}" "${extra[@]}" 2>&1 | tee "${OUT}/${name}.txt"; then
		failed+=("${name}")
		continue
	fi
	if ! grep -q '^PASS' "${OUT}/${name}.txt"; then
		failed+=("${name}")
		continue
	fi

	grep '^Benchmark' "${OUT}/${name}.txt" | tee -a "${OUT}/results.txt" | awk -v n="${name}" '
	{
		ns = b = a = in_ = "";
		for (i = 3; i < NF; i++) {
			if ($(i+1) == "ns/op") ns = $i;
			else if ($(i+1) == "B/op") b = $i;
			else if ($(i+1) == "allocs/op") a = $i;
			else if ($(i+1) == "inuse-B/op") in_ = $i;
		}
		printf "%s\t%s\t%s\t%s\t%s\t%s\n", n, $1, ns, b, a, in_;
	}' >> "${OUT}/summary.tsv"
done

echo
echo "Results written to ${OUT} (summary.tsv, results.txt, <name>.txt)"
column -t -s $'\t' "${OUT}/summary.tsv" 2>/dev/null || cat "${OUT}/summary.tsv"

if [[ ${#failed[@]} -gt 0 ]]; then
	echo "FAILED scenarios: ${failed[*]}" >&2
	exit 1
fi
