#!/usr/bin/env bash
# Run one real journey of tests/ against the skarbiec binary this release
# build staged, as a post-build test of .wisent-release.json.
#
# Usage: tests/release/journey.sh <journey>
#
# The journey drives the staged binary ($WISENT_OUTPUT_DIR/stage/bin/skarbiec),
# never one compiled again for the test, from the unpacked source Stado's
# build worker runs it in, which is not a git checkout, so the revision each
# report names is the one the worker declares (WISENT_SOURCE_COMMIT). Its
# report is copied into WISENT_TEST_EVIDENCE_DIR, the qualification output
# the worker retains with the release.
set -euo pipefail

refuse() {
  printf '%s\n' "$*" >/dev/stderr
  false
}

journey=${1:?name the journey to run: serve-one-process or vault-fence}
output_dir=${WISENT_OUTPUT_DIR:?WISENT_OUTPUT_DIR is required: Stado'"'"'s build worker names the output of the build under test}
evidence_dir=${WISENT_TEST_EVIDENCE_DIR:?WISENT_TEST_EVIDENCE_DIR is required: Stado'"'"'s build worker names the qualification output it retains}
revision=${WISENT_SOURCE_COMMIT:?WISENT_SOURCE_COMMIT is required: Stado'"'"'s build worker names the commit under test}
case "$journey" in
  serve-one-process) script=tests/serve/one_process.sh area=serve ;;
  vault-fence) script=tests/vault/fence.sh area=fence ;;
  *) refuse "no journey $journey; tests/release/journey.sh runs serve-one-process and vault-fence" ;;
esac
binary="$output_dir/stage/bin/skarbiec"
[[ -x "$binary" ]] || refuse "the build under test staged no executable $binary; release/build.sh stages it"
cd "$(dirname "$0")/../.."
[[ -f "$script" ]] || refuse "this source holds no $script for journey $journey"
for program in jq curl openssl; do
  command -v "$program" >/dev/null || refuse "journey $journey needs $program on PATH, and this builder has none"
done

status=0
SKARBIEC="$binary" SKARBIEC_TEST_SOURCE_REVISION="$revision" bash "$script" || status=$?
mkdir -p "$evidence_dir/$journey"
if [[ -d "target/real-tests/$area" ]]; then
  cp -R "target/real-tests/$area/." "$evidence_dir/$journey/"
else
  refuse "journey $journey left no report under target/real-tests/$area (exit $status)"
fi
exit "$status"
