#!/usr/bin/env bash
#
# Assert the library's normal dependency graph is exactly what we claim it is.
#
# The library manifest states "12 distinct crates, 0 proc-macro crates" as the reason
# a watch-only wallet tool can be audited by reading one file. This script is what
# stops that from drifting into a comment nobody re-checked.
#
# Runs on Linux, macOS and Windows (Git Bash / `shell: bash` in Actions).

set -euo pipefail

# Collation is part of the comparison, not a detail. Under C, `bitcoin-io` sorts
# before `bitcoin_hashes`; under en_US.UTF-8 punctuation is ignored and the two
# swap. Without this the check goes red or green depending on the runner's
# locale, which is the worst possible failure mode for a policy check.
export LC_ALL=C

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
expected_file="${repo_root}/ci/expected-library-crates.txt"

# `-e normal` excludes both dev- and build-dependencies. Build-dependencies are
# excluded on purpose: `cc` and `find-msvc-tools` compile secp256k1's C sources and
# are never linked into our library, so they are not part of the claim.
# awk rather than grep for the filtering. Under `set -euo pipefail`, a `grep -v`
# that matches nothing exits non-zero and kills the script — so an empty result
# would abort here instead of being reported as the difference it is.
actual="$(
    cargo tree --manifest-path "${repo_root}/Cargo.toml" \
        -p descriptor-addresses -e normal --prefix none |
        sed 's/ (\*)$//' |
        awk 'NF && $1 != "descriptor-addresses" { print $1 }' |
        sort -u
)"

expected="$(
    awk '!/^[[:space:]]*#/ && NF { print $1 }' "${expected_file}" |
        sort -u
)"

if [ "${actual}" != "${expected}" ]; then
    echo "FAIL: the library's normal dependency graph does not match ci/expected-library-crates.txt"
    echo
    echo "  < expected (in the whitelist, missing from the graph)"
    echo "  > actual   (in the graph, NOT in the whitelist)"
    echo
    diff <(echo "${expected}") <(echo "${actual}") || true
    echo
    echo "If this addition is intended, add it to the whitelist IN THE SAME COMMIT,"
    echo "and say in the message why the library needs it. If it is not intended,"
    echo "this is the check doing its job."
    exit 1
fi

count="$(echo "${actual}" | wc -l | tr -d '[:space:]')"
echo "OK: library normal graph is ${count} crates, matching the whitelist."
