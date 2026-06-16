#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SCRIPT="$REPO_ROOT/scanpkg.sh"

TEST_ROOT=""
TESTS_RUN=0

cleanup() {
  [[ -n "$TEST_ROOT" && -d "$TEST_ROOT" ]] && rm -rf -- "$TEST_ROOT"
}
trap cleanup EXIT

fail() {
  printf 'not ok %d - %s\n' "$TESTS_RUN" "$1" >&2
  exit 1
}

pass() {
  printf 'ok %d - %s\n' "$TESTS_RUN" "$1"
}

run_test() {
  local name="$1"
  shift

  TESTS_RUN=$((TESTS_RUN + 1))
  "$@" || fail "$name"
  pass "$name"
}

make_verdict() {
  jq -cn \
    --argjson malware "${1:-false}" \
    --argjson credential "${2:-false}" \
    --argjson destructive "${3:-false}" \
    --argjson obfuscated "${4:-false}" \
    --argjson runtime "${5:-false}" \
    --argjson new_install "${6:-false}" \
    --argjson install_suspicious "${7:-false}" \
    --argjson author "${8:-false}" \
    --argjson checksum "${9:-false}" \
    --argjson hook "${10:-false}" \
    --argjson sidecar "${11:-false}" \
    '{
      malware_suspected: $malware,
      credential_exfiltration: $credential,
      destructive_behavior: $destructive,
      obfuscated_payload: $obfuscated,
      new_runtime_or_toolchain: $runtime,
      new_install_script: $new_install,
      install_script_suspicious: $install_suspicious,
      package_hook_suspicious: $hook,
      sidecar_file_suspicious: $sidecar,
      new_or_unusual_author: $author,
      checksum_or_source_suspicious: $checksum,
      summary: "fixture verdict",
      evidence: ["fixture evidence"]
    }'
}

write_openai_response() {
  local verdict="$1"
  local path="$2"

  jq -n --arg text "$verdict" \
    '{output:[{type:"message",content:[{type:"output_text",text:$text}]}]}' > "$path"
}

setup_case() {
  local dir="$1"

  mkdir -p "$dir/fakebin"
  git -C "$dir" init -q

  cat > "$dir/fakebin/curl" <<'FAKE_CURL'
#!/usr/bin/env bash
set -uo pipefail

output_file=""
payload_ref=""

while (($#)); do
  case "$1" in
    -o)
      output_file="$2"
      shift 2
      ;;
    -d)
      payload_ref="$2"
      shift 2
      ;;
    *)
      shift
      ;;
  esac
done

if [[ -n "${SCANPKG_CAPTURE_PAYLOAD:-}" && "$payload_ref" == @* ]]; then
  cp "${payload_ref#@}" "$SCANPKG_CAPTURE_PAYLOAD"
fi

if [[ -n "${SCANPKG_CURL_COUNT:-}" ]]; then
  count=0
  if [[ -f "$SCANPKG_CURL_COUNT" ]]; then
    count="$(sed -n '1p' "$SCANPKG_CURL_COUNT")"
  fi
  printf '%s\n' "$((count + 1))" > "$SCANPKG_CURL_COUNT"
fi

if [[ "${SCANPKG_CURL_EXIT:-0}" != "0" ]]; then
  exit "$SCANPKG_CURL_EXIT"
fi

if [[ -n "$output_file" ]]; then
  cp "${SCANPKG_CURL_RESPONSE:?missing SCANPKG_CURL_RESPONSE}" "$output_file"
fi

printf '%s' "${SCANPKG_HTTP_CODE:-200}"
FAKE_CURL

  cat > "$dir/fakebin/makepkg" <<'FAKE_MAKEPKG'
#!/usr/bin/env bash
set -uo pipefail
printf '%s\n' "$@" > "${SCANPKG_MAKEPKG_ARGS:?missing SCANPKG_MAKEPKG_ARGS}"
exit 0
FAKE_MAKEPKG

  chmod +x "$dir/fakebin/curl" "$dir/fakebin/makepkg"
}

write_pkgbuild() {
  local dir="$1"
  local content="$2"
  printf '%s\n' "$content" > "$dir/PKGBUILD"
}

commit_all() {
  local dir="$1"
  local author_name="$2"
  local author_email="$3"
  local message="$4"

  git -C "$dir" add PKGBUILD
  git -C "$dir" \
    -c user.name="$author_name" \
    -c user.email="$author_email" \
    commit -q --author="$author_name <$author_email>" -m "$message"
}

run_scan() {
  local dir="$1"
  local script="${SCANPKG_TEST_SCRIPT:-$SCRIPT}"
  shift

  (
    cd "$dir" || exit 1
    PATH="$dir/fakebin:$PATH" \
      SCANPKG_LOAD_ENV="${SCANPKG_LOAD_ENV-0}" \
      VERBOSE="${SCANPKG_TEST_VERBOSE-0}" \
      SCANPKG_ALLOW_FAILED_PACKAGES="${SCANPKG_TEST_ALLOW_FAILED_PACKAGES-}" \
      SCANPKG_CACHE_DIR="${SCANPKG_TEST_CACHE_DIR:-$dir/cache}" \
      SCANPKG_CACHE_TTL_SECONDS="${SCANPKG_TEST_CACHE_TTL_SECONDS:-3600}" \
      OPENAI_API_KEY="${OPENAI_API_KEY-}" \
      MAKEPKG_BIN="$dir/fakebin/makepkg" \
      SCANPKG_CURL_RESPONSE="$dir/response.json" \
      SCANPKG_CAPTURE_PAYLOAD="$dir/payload.json" \
      SCANPKG_CURL_COUNT="$dir/curl.count" \
      SCANPKG_MAKEPKG_ARGS="$dir/makepkg.args" \
      "$script" "$@"
  )
}

test_syntax() {
  bash -n "$SCRIPT"
}

test_clean_calls_makepkg() {
  local dir="$TEST_ROOT/clean"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=clean'
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" --syncdeps --noconfirm
  [[ -f "$dir/makepkg.args" ]]
  grep -qx -- '--syncdeps' "$dir/makepkg.args"
  grep -qx -- '--noconfirm' "$dir/makepkg.args"
}

test_critical_blocks() {
  local dir="$TEST_ROOT/critical"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=bad'
  write_openai_response "$(make_verdict true)" "$dir/response.json"

  if OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null 2>&1; then
    return 1
  fi
  [[ ! -f "$dir/makepkg.args" ]]
}

test_reject_prints_allowlist_instruction() {
  local dir="$TEST_ROOT/reject-instruction"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=blocked-pkg'
  write_openai_response "$(make_verdict true)" "$dir/response.json"

  if OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null 2>"$dir/stderr.log"; then
    return 1
  fi

  grep -q 'SCANPKG_ALLOW_FAILED_PACKAGES="blocked-pkg"' "$dir/stderr.log"
  grep -q 'temporarily whitelist this package' "$dir/stderr.log"
  [[ ! -f "$dir/makepkg.args" ]]
}

test_allowlisted_rejection_calls_makepkg() {
  local dir="$TEST_ROOT/allowlisted-reject"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=blocked-pkg'
  write_openai_response "$(make_verdict true)" "$dir/response.json"

  SCANPKG_TEST_ALLOW_FAILED_PACKAGES=blocked-pkg OPENAI_API_KEY=test-key run_scan "$dir" --needed >/dev/null 2>"$dir/stderr.log"
  [[ -f "$dir/makepkg.args" ]]
  grep -qx -- '--needed' "$dir/makepkg.args"
  grep -q 'temporarily whitelisted' "$dir/stderr.log"
}

test_threshold_blocks() {
  local dir="$TEST_ROOT/threshold"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=threshold'
  write_openai_response "$(make_verdict false false false false true true)" "$dir/response.json"

  if OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null 2>&1; then
    return 1
  fi
  [[ ! -f "$dir/makepkg.args" ]]
}

test_single_noncritical_allows() {
  local dir="$TEST_ROOT/single"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=single'
  write_openai_response "$(make_verdict false false false false false true)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  [[ -f "$dir/makepkg.args" ]]
}

test_missing_api_key_blocks() {
  local dir="$TEST_ROOT/no-key"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=no-key'
  write_openai_response "$(make_verdict)" "$dir/response.json"

  if SCANPKG_LOAD_ENV=0 OPENAI_API_KEY= run_scan "$dir" >/dev/null 2>&1; then
    return 1
  fi
  [[ ! -f "$dir/payload.json" ]]
}

test_single_install_in_payload() {
  local dir="$TEST_ROOT/install-one"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=install-one"$'\n'"install=premake-git-deps.install"
  printf '%s\n' 'post_install() { echo installed; }' > "$dir/premake-git-deps.install"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Install script: premake-git-deps.install") and contains("post_install"))' "$dir/payload.json" >/dev/null
}

test_multiple_installs_in_payload() {
  local dir="$TEST_ROOT/install-multiple"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=install-multiple"$'\n'"install=one.install"$'\n'"install='two.install'"
  printf '%s\n' 'post_install() { echo one; }' > "$dir/one.install"
  printf '%s\n' 'post_install() { echo two; }' > "$dir/two.install"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Install script: one.install") and contains("echo one"))' "$dir/payload.json" >/dev/null
  jq -e '.input[].content | select(contains("Install script: two.install") and contains("echo two"))' "$dir/payload.json" >/dev/null
}

test_missing_install_warning() {
  local dir="$TEST_ROOT/install-missing"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=install-missing"$'\n'"install=missing.install"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Missing install script: missing.install") and contains("WARNING"))' "$dir/payload.json" >/dev/null
}

test_variable_install_in_payload() {
  local dir="$TEST_ROOT/install-variable"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=resolved"$'\n'"install=\$pkgname.install"
  printf '%s\n' 'post_upgrade() { echo resolved; }' > "$dir/resolved.install"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Install script: resolved.install") and contains("post_upgrade"))' "$dir/payload.json" >/dev/null
}

test_changelog_in_payload() {
  local dir="$TEST_ROOT/changelog"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=changelog"$'\n'"changelog=NEWS"
  printf '%s\n' 'security relevant packaging note' > "$dir/NEWS"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Package sidecar file (changelog): NEWS") and contains("security relevant packaging note"))' "$dir/payload.json" >/dev/null
}

test_missing_changelog_warning() {
  local dir="$TEST_ROOT/changelog-missing"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=changelog-missing"$'\n'"changelog=missing.NEWS"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Missing package sidecar file (changelog): missing.NEWS") and contains("WARNING"))' "$dir/payload.json" >/dev/null
}

test_local_source_patch_in_payload() {
  local dir="$TEST_ROOT/source-patch"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=source-patch"$'\n'"source=("$'\n'"  'renamed.patch::fix.patch'"$'\n'"  'git+https://example.test/repo.git#commit=abc'"$'\n'")"
  printf '%s\n' 'diff --git a/a b/a' '+ suspicious patch context' > "$dir/fix.patch"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Package sidecar file (local source): fix.patch") and contains("suspicious patch context"))' "$dir/payload.json" >/dev/null
}

test_top_level_hook_in_payload() {
  local dir="$TEST_ROOT/top-level-hook"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=top-level-hook'
  printf '%s\n' '[Action]' 'When = PostTransaction' 'Exec = /usr/bin/sh -c id' > "$dir/scanpkg-test.hook"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Package sidecar file (top-level high-risk file): scanpkg-test.hook") and contains("Exec = /usr/bin/sh -c id"))' "$dir/payload.json" >/dev/null
}

test_committed_diff_in_payload() {
  local dir="$TEST_ROOT/diff"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=diff"$'\n'"pkgver=1"
  commit_all "$dir" Alice alice@example.test "v1"
  write_pkgbuild "$dir" "pkgname=diff"$'\n'"pkgver=2"
  commit_all "$dir" Alice alice@example.test "v2"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("Committed PKGBUILD diff") and contains("-pkgver=1") and contains("+pkgver=2"))' "$dir/payload.json" >/dev/null
}

test_new_author_signal() {
  local dir="$TEST_ROOT/author"
  setup_case "$dir"
  local i
  for i in 1 2 3 4; do
    write_pkgbuild "$dir" "pkgname=author"$'\n'"pkgver=$i"
    commit_all "$dir" Old old@example.test "old $i"
  done
  write_pkgbuild "$dir" "pkgname=author"$'\n'"pkgver=5"
  commit_all "$dir" New new@example.test "new"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.input[].content | select(contains("latest_author_is_new=true"))' "$dir/payload.json" >/dev/null
}

test_store_false() {
  local dir="$TEST_ROOT/store"
  setup_case "$dir"
  write_pkgbuild "$dir" 'pkgname=store'
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq -e '.store == false' "$dir/payload.json" >/dev/null
  jq -e '.text.format.schema.required | index("network_fetch_in_build") | not' "$dir/payload.json" >/dev/null
  jq -e '.text.format.schema.properties | has("network_fetch_in_build") | not' "$dir/payload.json" >/dev/null
  jq -e '.text.format.schema.required | index("package_hook_suspicious")' "$dir/payload.json" >/dev/null
  jq -e '.text.format.schema.required | index("sidecar_file_suspicious")' "$dir/payload.json" >/dev/null
}

test_cached_response_reused_for_same_version() {
  local dir="$TEST_ROOT/cache-reuse"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=cache-pkg"$'\n'"pkgver=1.0"$'\n'"pkgrel=1"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  write_openai_response "$(make_verdict true)" "$dir/response.json"
  rm -f "$dir/makepkg.args"
  OPENAI_API_KEY=test-key run_scan "$dir" --cached >/dev/null

  [[ "$(sed -n '1p' "$dir/curl.count")" == "1" ]]
  grep -qx -- '--cached' "$dir/makepkg.args"
  jq -e '.version == "1.0-1" and .schema_version == 2 and (.response | type == "object")' "$dir/cache/cache-pkg.lock" >/dev/null
}

test_cache_version_mismatch_refreshes() {
  local dir="$TEST_ROOT/cache-version"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=cache-pkg"$'\n'"pkgver=1.0"$'\n'"pkgrel=1"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  write_pkgbuild "$dir" "pkgname=cache-pkg"$'\n'"pkgver=2.0"$'\n'"pkgrel=1"
  write_openai_response "$(make_verdict true)" "$dir/response.json"

  if OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null 2>&1; then
    return 1
  fi
  [[ "$(sed -n '1p' "$dir/curl.count")" == "2" ]]
}

test_expired_cache_refreshes() {
  local dir="$TEST_ROOT/cache-expired"
  setup_case "$dir"
  write_pkgbuild "$dir" "pkgname=cache-pkg"$'\n'"pkgver=1.0"$'\n'"pkgrel=1"
  write_openai_response "$(make_verdict)" "$dir/response.json"

  OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null
  jq '.cached_at = 0' "$dir/cache/cache-pkg.lock" > "$dir/cache/cache-pkg.tmp"
  mv "$dir/cache/cache-pkg.tmp" "$dir/cache/cache-pkg.lock"
  write_openai_response "$(make_verdict true)" "$dir/response.json"

  if OPENAI_API_KEY=test-key run_scan "$dir" >/dev/null 2>&1; then
    return 1
  fi
  [[ "$(sed -n '1p' "$dir/curl.count")" == "2" ]]
}

test_script_dir_env_and_verbose() {
  local dir="$TEST_ROOT/env-verbose"
  local script_dir="$dir/script-dir"
  setup_case "$dir"
  mkdir -p "$script_dir"
  cp "$SCRIPT" "$script_dir/scanpkg.sh"
  chmod +x "$script_dir/scanpkg.sh"

  write_pkgbuild "$dir" 'pkgname=env-verbose'
  write_openai_response "$(make_verdict)" "$dir/response.json"
  printf '%s\n' \
    'OPENAI_API_KEY=dotenv-key' \
    'OPENAI_MODEL=dotenv-model' \
    'VERBOSE=1' > "$script_dir/.env"

  SCANPKG_TEST_SCRIPT="$script_dir/scanpkg.sh" SCANPKG_LOAD_ENV=1 OPENAI_API_KEY= run_scan "$dir" >/dev/null 2>"$dir/stderr.log"
  jq -e '.model == "dotenv-model"' "$dir/payload.json" >/dev/null
  grep -q 'scanpkg: OpenAI request endpoint:' "$dir/stderr.log"
  grep -q 'scanpkg: OpenAI request body:' "$dir/stderr.log"
  grep -q 'scanpkg: OpenAI response body:' "$dir/stderr.log"
  grep -q '"model": "dotenv-model"' "$dir/stderr.log"
  grep -q '"output"' "$dir/stderr.log"
  ! grep -q 'dotenv-key' "$dir/stderr.log"
}

TEST_ROOT="$(mktemp -d)"

run_test 'bash syntax' test_syntax
run_test 'clean verdict calls makepkg' test_clean_calls_makepkg
run_test 'critical verdict blocks' test_critical_blocks
run_test 'rejected build prints allowlist instruction' test_reject_prints_allowlist_instruction
run_test 'allowlisted rejected build calls makepkg' test_allowlisted_rejection_calls_makepkg
run_test 'threshold verdict blocks' test_threshold_blocks
run_test 'single noncritical allows' test_single_noncritical_allows
run_test 'missing API key blocks' test_missing_api_key_blocks
run_test 'single install script included' test_single_install_in_payload
run_test 'multiple install scripts included' test_multiple_installs_in_payload
run_test 'missing install script warning included' test_missing_install_warning
run_test 'variable install script included' test_variable_install_in_payload
run_test 'changelog included' test_changelog_in_payload
run_test 'missing changelog warning included' test_missing_changelog_warning
run_test 'local source patch included' test_local_source_patch_in_payload
run_test 'top-level hook included' test_top_level_hook_in_payload
run_test 'committed diff included' test_committed_diff_in_payload
run_test 'new author signal included' test_new_author_signal
run_test 'store false included' test_store_false
run_test 'cached response reused for same version' test_cached_response_reused_for_same_version
run_test 'cache version mismatch refreshes' test_cache_version_mismatch_refreshes
run_test 'expired cache refreshes' test_expired_cache_refreshes
run_test 'script dir .env and verbose request logging' test_script_dir_env_and_verbose
