#!/usr/bin/env bash

set -uo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${SCANPKG_ENV_FILE:-$SCRIPT_DIR/.env}"

if [[ "${SCANPKG_LOAD_ENV:-1}" == "1" && -f "$ENV_FILE" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$ENV_FILE"
  set +a
fi

# User configuration.
OPENAI_API_MODE="${OPENAI_API_MODE:-responses}"
OPENAI_ENDPOINT="${OPENAI_ENDPOINT:-https://api.openai.com/v1/responses}"
OPENAI_MODEL="${OPENAI_MODEL:-gpt-5.4}"
OPENAI_API_KEY="${OPENAI_API_KEY:-}"
OPENAI_REASONING_EFFORT="${OPENAI_REASONING_EFFORT:-medium}"
OPENAI_STORE="${OPENAI_STORE:-false}"

RISK_ABORT_THRESHOLD="${RISK_ABORT_THRESHOLD:-2}"
CRITICAL_RISK_KEYS="${CRITICAL_RISK_KEYS:-malware_suspected credential_exfiltration destructive_behavior obfuscated_payload install_script_suspicious}"
SCANPKG_ALLOW_FAILED_PACKAGES="${SCANPKG_ALLOW_FAILED_PACKAGES:-}"
FAIL_CLOSED="${FAIL_CLOSED:-1}"

MAKEPKG_BIN="${MAKEPKG_BIN:-/usr/bin/makepkg}"
CURL_TIMEOUT_SECONDS="${CURL_TIMEOUT_SECONDS:-120}"
MAX_CONTEXT_BYTES="${MAX_CONTEXT_BYTES:-250000}"
CACHE_DIR="${SCANPKG_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME:-}/.cache}/scanpkg}"
CACHE_TTL_SECONDS="${SCANPKG_CACHE_TTL_SECONDS:-3600}"
VERBOSE="${VERBOSE:-1}"

SYSTEM_PROMPT="${SYSTEM_PROMPT:-You review Arch Linux PKGBUILD files for malware risk. Return only the requested JSON. Treat as suspicious: obfuscated shell, credential access or exfiltration, destructive commands outside build dirs, checksum bypasses, suspicious source URL changes, newly added install scripts, install hooks that run commands as root, and random introduction of runtimes/toolchains such as node/npm/npx/yarn/pnpm/bun/deno/go/cargo/python/pip/ruby when not previously present. A new recent author is a risk signal when paired with suspicious changes. Prefer blocking only when evidence is concrete.}"

RISK_KEYS=(
  malware_suspected
  credential_exfiltration
  destructive_behavior
  obfuscated_payload
  new_runtime_or_toolchain
  new_install_script
  install_script_suspicious
  new_or_unusual_author
  checksum_or_source_suspicious
)

REQUIRED_KEYS=(
  "${RISK_KEYS[@]}"
  summary
  evidence
)

INPUT_JSON="[]"
TOTAL_CONTEXT_BYTES=0
MAKEPKG_ARGS=()
PACKAGE_NAMES=()
PACKAGE_VERSION=""

cleanup_files=()

cleanup() {
  local file
  for file in "${cleanup_files[@]}"; do
    [[ -n "$file" && -e "$file" ]] && rm -f -- "$file"
  done
}
trap cleanup EXIT

join_by_newline() {
  local item
  for item in "$@"; do
    printf '%s\n' "$item"
  done
}

die() {
  printf 'scanpkg: %s\n' "$1" >&2
  exit 1
}

scanner_failed() {
  local message="$1"

  if [[ "$FAIL_CLOSED" == "1" ]]; then
    die "scanner failed: $message"
  fi

  printf 'scanpkg: scanner failed: %s; continuing because FAIL_CLOSED=0\n' "$message" >&2
  exec "$MAKEPKG_BIN" "${MAKEPKG_ARGS[@]}"
}

require_command() {
  local name="$1"
  command -v "$name" >/dev/null 2>&1 || scanner_failed "missing required command: $name"
}

is_json_bool() {
  [[ "$1" == "true" || "$1" == "false" ]]
}

is_verbose() {
  [[ "$VERBOSE" == "1" || "$VERBOSE" == "true" || "$VERBOSE" == "yes" ]]
}

verbose_log() {
  is_verbose || return 0
  printf 'scanpkg: %s\n' "$1" >&2
}

add_user_message() {
  local title="$1"
  local body="$2"
  local content
  local remaining

  if (( TOTAL_CONTEXT_BYTES >= MAX_CONTEXT_BYTES )); then
    return 0
  fi

  content="## ${title}"$'\n\n'"${body}"
  remaining=$((MAX_CONTEXT_BYTES - TOTAL_CONTEXT_BYTES))

  if (( ${#content} > remaining )); then
    content="${content:0:remaining}"$'\n''[scanpkg: context truncated at MAX_CONTEXT_BYTES]'
  fi

  TOTAL_CONTEXT_BYTES=$((TOTAL_CONTEXT_BYTES + ${#content}))
  INPUT_JSON="$(jq -c --arg content "$content" '. + [{"role":"user","content":$content}]' <<<"$INPUT_JSON")" \
    || scanner_failed "failed to build OpenAI input JSON"
}

read_file_or_empty() {
  local path="$1"
  [[ -f "$path" ]] || return 0
  sed -n '1,$p' "$path"
}

collect_pkgbuild_history() {
  local commits=()
  local diff_output

  mapfile -t commits < <(git log --follow --format=%H -- PKGBUILD 2>/dev/null | head -n 2)

  if (( ${#commits[@]} >= 2 )); then
    diff_output="$(git diff "${commits[1]}" "${commits[0]}" -- PKGBUILD 2>&1)"
    add_user_message "Committed PKGBUILD diff between latest two versions" "$diff_output"
  elif (( ${#commits[@]} == 1 )); then
    diff_output="$(git show --format= -- PKGBUILD 2>&1)"
    add_user_message "Only committed PKGBUILD version" "$diff_output"
  else
    add_user_message "Committed PKGBUILD history" "no committed PKGBUILD history found"
  fi
}

collect_worktree_diff() {
  local diff_output

  diff_output="$(git diff -- PKGBUILD 2>&1)"
  if [[ -n "$diff_output" ]]; then
    add_user_message "Current worktree PKGBUILD diff" "$diff_output"
  else
    add_user_message "Current worktree PKGBUILD diff" "no uncommitted tracked PKGBUILD diff found"
  fi
}

collect_authors() {
  local authors=()
  local latest_author_is_new=false
  local latest_author
  local author
  local details

  mapfile -t authors < <(git log -5 --format='%an <%ae>' 2>/dev/null)

  if (( ${#authors[@]} >= 2 )); then
    latest_author="${authors[0]}"
    latest_author_is_new=true
    for author in "${authors[@]:1}"; do
      if [[ "$author" == "$latest_author" ]]; then
        latest_author_is_new=false
        break
      fi
    done
  fi

  if (( ${#authors[@]} > 0 )); then
    details="latest_author_is_new=${latest_author_is_new}"$'\n''last_5_authors:'$'\n'"$(join_by_newline "${authors[@]}")"
  else
    details="latest_author_is_new=false"$'\n''last_5_authors: no commits found'
  fi

  add_user_message "Recent git authors" "$details"
}

strip_outer_quotes() {
  local value="$1"

  if [[ ${#value} -ge 2 ]]; then
    if [[ "${value:0:1}" == "'" && "${value: -1}" == "'" ]]; then
      value="${value:1:${#value}-2}"
    elif [[ "${value:0:1}" == '"' && "${value: -1}" == '"' ]]; then
      value="${value:1:${#value}-2}"
    fi
  fi

  printf '%s' "$value"
}

collect_package_names() {
  local line
  local trimmed
  local without_comment
  local rhs
  local token
  local names=()

  while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ "$trimmed" == \#* ]] && continue

    without_comment="${line%%#*}"
    if [[ "$without_comment" =~ ^[[:space:]]*pkgname[[:space:]]*=[[:space:]]*(.+)$ ]]; then
      rhs="${BASH_REMATCH[1]}"
      rhs="${rhs#"${rhs%%[![:space:]]*}"}"
      rhs="${rhs%"${rhs##*[![:space:]]}"}"

      if [[ "$rhs" == \(* && "$rhs" == *\) ]]; then
        rhs="${rhs#\(}"
        rhs="${rhs%\)}"
      fi

      for token in $rhs; do
        token="$(strip_outer_quotes "$token")"
        [[ -z "$token" || "$token" == \$* ]] && continue
        names+=("$token")
      done
      break
    fi
  done < PKGBUILD

  if (( ${#names[@]} == 0 )); then
    names+=("$(basename "$PWD")")
  fi

  PACKAGE_NAMES=("${names[@]}")
}

extract_pkgbuild_scalar() {
  local key="$1"
  local line
  local trimmed
  local without_comment
  local value

  while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ "$trimmed" == \#* ]] && continue

    without_comment="${line%%#*}"
    if [[ "$without_comment" =~ ^[[:space:]]*${key}[[:space:]]*=[[:space:]]*([^[:space:];]+) ]]; then
      value="${BASH_REMATCH[1]}"
      value="$(strip_outer_quotes "$value")"
      printf '%s' "$value"
      return 0
    fi
  done < PKGBUILD

  return 1
}

collect_package_version() {
  local epoch
  local pkgver
  local pkgrel
  local version

  epoch="$(extract_pkgbuild_scalar epoch || true)"
  pkgver="$(extract_pkgbuild_scalar pkgver || true)"
  pkgrel="$(extract_pkgbuild_scalar pkgrel || true)"

  if [[ -z "$pkgver" ]]; then
    PACKAGE_VERSION="unknown"
    return 0
  fi

  version="$pkgver"
  if [[ -n "$epoch" ]]; then
    version="${epoch}:${version}"
  fi
  if [[ -n "$pkgrel" ]]; then
    version="${version}-${pkgrel}"
  fi

  PACKAGE_VERSION="$version"
}

cache_package_key() {
  local package_name="$1"
  printf '%s' "$package_name" | sed 's/[^A-Za-z0-9._+-]/_/g'
}

cache_file_for_package() {
  local package_name="$1"
  local key

  key="$(cache_package_key "$package_name")"
  printf '%s/%s.lock' "$CACHE_DIR" "$key"
}

ensure_cache_dir() {
  [[ -n "$CACHE_DIR" ]] || return 1
  mkdir -p "$CACHE_DIR" 2>/dev/null
}

load_cached_response() {
  local now
  local package_name
  local cache_file
  local response

  [[ "$CACHE_TTL_SECONDS" =~ ^[0-9]+$ ]] || scanner_failed "SCANPKG_CACHE_TTL_SECONDS must be a non-negative integer"
  ensure_cache_dir || return 1

  now="$(date +%s)"
  for package_name in "${PACKAGE_NAMES[@]}"; do
    cache_file="$(cache_file_for_package "$package_name")"
    [[ -f "$cache_file" ]] || continue

    if jq -e \
      --arg version "$PACKAGE_VERSION" \
      --argjson now "$now" \
      --argjson ttl "$CACHE_TTL_SECONDS" \
      '.version == $version and
       (.cached_at | type == "number") and
       (($now - .cached_at) <= $ttl) and
       (.response | type == "object")' \
      "$cache_file" >/dev/null 2>&1; then
      response="$(jq -c '.response' "$cache_file" 2>/dev/null)" || continue
      verbose_log "using cached OpenAI response from $cache_file"
      if is_verbose; then
        printf 'scanpkg: OpenAI response body:\n%s\n' "$response" >&2
      fi
      printf '%s' "$response"
      return 0
    fi
  done

  return 1
}

store_cached_response() {
  local response_json="$1"
  local now
  local package_name
  local cache_file
  local tmp_file

  ensure_cache_dir || return 0

  now="$(date +%s)"
  for package_name in "${PACKAGE_NAMES[@]}"; do
    cache_file="$(cache_file_for_package "$package_name")"
    tmp_file="${cache_file}.$$"

    if jq -n \
      --arg package_name "$package_name" \
      --arg version "$PACKAGE_VERSION" \
      --argjson cached_at "$now" \
      --argjson response "$response_json" \
      '{
        package_name: $package_name,
        version: $version,
        cached_at: $cached_at,
        response: $response
      }' > "$tmp_file" 2>/dev/null; then
      mv -f "$tmp_file" "$cache_file"
      verbose_log "stored OpenAI response cache in $cache_file"
    else
      rm -f "$tmp_file"
      verbose_log "failed to store OpenAI response cache for $package_name"
    fi
  done
}

package_is_allowlisted() {
  local package_name="$1"
  local raw="$SCANPKG_ALLOW_FAILED_PACKAGES"
  local item

  raw="${raw//,/ }"
  for item in $raw; do
    item="$(strip_outer_quotes "$item")"
    if [[ "$item" == "$package_name" ]]; then
      return 0
    fi
  done

  return 1
}

any_package_is_allowlisted() {
  local package_name

  for package_name in "${PACKAGE_NAMES[@]}"; do
    if package_is_allowlisted "$package_name"; then
      return 0
    fi
  done

  return 1
}

package_names_for_display() {
  if (( ${#PACKAGE_NAMES[@]} > 0 )); then
    join_by_newline "${PACKAGE_NAMES[@]}" | tr '\n' ' ' | sed 's/[[:space:]]*$//'
  else
    basename "$PWD"
  fi
}

print_allowlist_instructions() {
  local package_names

  package_names="$(package_names_for_display)"
  printf 'scanpkg: to temporarily whitelist this package for a rejected build, rerun with:\n' >&2
  printf 'scanpkg:   SCANPKG_ALLOW_FAILED_PACKAGES="%s" %s <makepkg args>\n' "$package_names" "$(basename "$0")" >&2
  printf 'scanpkg: or add SCANPKG_ALLOW_FAILED_PACKAGES="%s" to %s for this wrapper.\n' "$package_names" "$ENV_FILE" >&2
}

collect_install_scripts() {
  local line
  local trimmed
  local without_comment
  local rest
  local match
  local value
  local scripts=()
  local script
  local content

  while IFS= read -r line || [[ -n "$line" ]]; do
    trimmed="${line#"${line%%[![:space:]]*}"}"
    [[ "$trimmed" == \#* ]] && continue

    without_comment="${line%%#*}"
    rest="$without_comment"

    while [[ "$rest" =~ (^|[[:space:];])install[[:space:]]*=[[:space:]]*([^[:space:];]+) ]]; do
      match="${BASH_REMATCH[0]}"
      value="${BASH_REMATCH[2]}"
      value="$(strip_outer_quotes "$value")"

      if [[ -n "$value" ]]; then
        scripts+=("$value")
      fi

      rest="${rest#*"$match"}"
    done
  done < PKGBUILD

  if (( ${#scripts[@]} == 0 )); then
    add_user_message "PKGBUILD install scripts" "no install= scripts referenced"
    return 0
  fi

  declare -A seen=()
  for script in "${scripts[@]}"; do
    [[ -n "${seen[$script]+set}" ]] && continue
    seen["$script"]=1

    if [[ -f "$script" ]]; then
      content="$(read_file_or_empty "$script")"
      add_user_message "Install script: ${script}" "$content"
    else
      add_user_message "Missing install script: ${script}" "WARNING: PKGBUILD references install=${script}, but the file was not found in the current directory."
    fi
  done
}

risk_keys_json() {
  printf '%s\n' "${RISK_KEYS[@]}" | jq -R . | jq -cs .
}

required_keys_json() {
  printf '%s\n' "${REQUIRED_KEYS[@]}" | jq -R . | jq -cs .
}

build_request_json() {
  local risk_schema
  local store_bool="$OPENAI_STORE"

  is_json_bool "$store_bool" || scanner_failed "OPENAI_STORE must be true or false"

  risk_schema="$(jq -n '
    {
      type: "object",
      additionalProperties: false,
      required: [
        "malware_suspected",
        "credential_exfiltration",
        "destructive_behavior",
        "obfuscated_payload",
        "new_runtime_or_toolchain",
        "new_install_script",
        "install_script_suspicious",
        "new_or_unusual_author",
        "checksum_or_source_suspicious",
        "summary",
        "evidence"
      ],
      properties: {
        malware_suspected: {type: "boolean"},
        credential_exfiltration: {type: "boolean"},
        destructive_behavior: {type: "boolean"},
        obfuscated_payload: {type: "boolean"},
        new_runtime_or_toolchain: {type: "boolean"},
        new_install_script: {type: "boolean"},
        install_script_suspicious: {type: "boolean"},
        new_or_unusual_author: {type: "boolean"},
        checksum_or_source_suspicious: {type: "boolean"},
        summary: {type: "string"},
        evidence: {type: "array", items: {type: "string"}}
      }
    }
  ')" || scanner_failed "failed to build response schema"

  jq -n \
    --arg model "$OPENAI_MODEL" \
    --arg instructions "$SYSTEM_PROMPT" \
    --arg effort "$OPENAI_REASONING_EFFORT" \
    --argjson store "$store_bool" \
    --argjson input "$INPUT_JSON" \
    --argjson schema "$risk_schema" \
    '{
      model: $model,
      store: $store,
      reasoning: {effort: $effort},
      instructions: $instructions,
      input: $input,
      text: {
        format: {
          type: "json_schema",
          name: "pkgbuild_malware_scan",
          strict: true,
          schema: $schema
        }
      }
    }'
}

call_openai() {
  local request_json="$1"
  local request_file
  local response_file
  local curl_output
  local curl_status
  local http_code

  request_file="$(mktemp)"
  response_file="$(mktemp)"
  cleanup_files+=("$request_file" "$response_file")

  printf '%s' "$request_json" > "$request_file"

  if is_verbose; then
    verbose_log "OpenAI request endpoint: $OPENAI_ENDPOINT"
    verbose_log "OpenAI request headers: Content-Type: application/json; Authorization: Bearer [redacted]"
    printf 'scanpkg: OpenAI request body:\n%s\n' "$request_json" >&2
  fi

  curl_output="$(curl -sS \
    --max-time "$CURL_TIMEOUT_SECONDS" \
    -o "$response_file" \
    -w '%{http_code}' \
    -H 'Content-Type: application/json' \
    -H "Authorization: Bearer ${OPENAI_API_KEY}" \
    -d @"$request_file" \
    "$OPENAI_ENDPOINT" 2>&1)"
  curl_status=$?

  if (( curl_status != 0 )); then
    scanner_failed "curl failed with exit ${curl_status}: ${curl_output}"
  fi

  if is_verbose; then
    printf 'scanpkg: OpenAI response body:\n' >&2
    sed -n '1,$p' "$response_file" >&2
    printf '\n' >&2
  fi

  http_code="$curl_output"
  if [[ ! "$http_code" =~ ^2[0-9][0-9]$ ]]; then
    local body
    body="$(sed -n '1,20p' "$response_file" 2>/dev/null)"
    scanner_failed "OpenAI API returned HTTP ${http_code}: ${body}"
  fi

  sed -n '1,$p' "$response_file"
}

extract_verdict_json() {
  local response_json="$1"
  local api_error
  local output_text
  local verdict

  api_error="$(jq -r '.error.message? // empty' <<<"$response_json" 2>/dev/null)" \
    || scanner_failed "OpenAI response was not valid JSON"

  if [[ -n "$api_error" ]]; then
    scanner_failed "OpenAI API error: $api_error"
  fi

  output_text="$(jq -er '
    .output_text //
    ([.output[]? | select(.type == "message") | .content[]? | select(.type == "output_text") | .text] | join("\n"))
    | select(length > 0)
  ' <<<"$response_json" 2>/dev/null)" || scanner_failed "no output text found in OpenAI response"

  verdict="$(jq -c '.' <<<"$output_text" 2>/dev/null)" \
    || scanner_failed "model output was not valid JSON"

  validate_verdict "$verdict"
  printf '%s' "$verdict"
}

validate_verdict() {
  local verdict="$1"
  local key
  local allowed

  allowed="$(required_keys_json)" || scanner_failed "failed to build key validator"

  jq -e --argjson allowed "$allowed" '
    type == "object" and
    ((keys_unsorted - $allowed) | length == 0)
  ' <<<"$verdict" >/dev/null || scanner_failed "verdict JSON contained unexpected keys or was not an object"

  for key in "${RISK_KEYS[@]}"; do
    jq -e --arg key "$key" 'has($key) and (.[$key] | type == "boolean")' <<<"$verdict" >/dev/null \
      || scanner_failed "verdict JSON missing boolean key: $key"
  done

  jq -e 'has("summary") and (.summary | type == "string")' <<<"$verdict" >/dev/null \
    || scanner_failed "verdict JSON missing string key: summary"
  jq -e 'has("evidence") and (.evidence | type == "array") and all(.evidence[]; type == "string")' <<<"$verdict" >/dev/null \
    || scanner_failed "verdict JSON missing string array key: evidence"
}

evaluate_verdict() {
  local verdict="$1"
  local keys_json
  local risk_count
  local triggered
  local critical_triggered=()
  local key
  local summary

  keys_json="$(risk_keys_json)" || scanner_failed "failed to build risk key list"
  risk_count="$(jq -r --argjson keys "$keys_json" '. as $verdict | [ $keys[] | select($verdict[.] == true) ] | length' <<<"$verdict")" \
    || scanner_failed "failed to count risk booleans"
  triggered="$(jq -r --argjson keys "$keys_json" '. as $verdict | [ $keys[] | select($verdict[.] == true) ] | join(" ")' <<<"$verdict")" \
    || scanner_failed "failed to list triggered risk booleans"

  for key in $CRITICAL_RISK_KEYS; do
    if jq -e --arg key "$key" '.[$key] == true' <<<"$verdict" >/dev/null; then
      critical_triggered+=("$key")
    fi
  done

  if (( ${#critical_triggered[@]} > 0 || risk_count >= RISK_ABORT_THRESHOLD )); then
    summary="$(jq -r '.summary' <<<"$verdict")"
    if any_package_is_allowlisted; then
      printf 'scanpkg: allowing rejected PKGBUILD because package is temporarily whitelisted: %s\n' "$(package_names_for_display)" >&2
      printf 'scanpkg: scanner verdict was: %s\n' "$summary" >&2
      printf 'scanpkg: triggered risk keys: %s\n' "${triggered:-none}" >&2
      return 0
    fi

    printf 'scanpkg: blocked PKGBUILD: %s\n' "$summary" >&2
    printf 'scanpkg: triggered risk keys: %s\n' "${triggered:-none}" >&2
    if (( ${#critical_triggered[@]} > 0 )); then
      printf 'scanpkg: critical risk keys: %s\n' "$(join_by_newline "${critical_triggered[@]}" | tr '\n' ' ' | sed 's/[[:space:]]*$//')" >&2
    fi
    print_allowlist_instructions
    exit 1
  fi
}

main() {
  local request_json
  local response_json
  local verdict_json
  local pkgbuild_content

  MAKEPKG_ARGS=("$@")

  [[ "$OPENAI_API_MODE" == "responses" ]] || scanner_failed "unsupported OPENAI_API_MODE: $OPENAI_API_MODE"
  [[ -n "$OPENAI_API_KEY" ]] || scanner_failed "missing OPENAI_API_KEY"
  [[ -f PKGBUILD ]] || scanner_failed "missing PKGBUILD in current directory"
  [[ "$RISK_ABORT_THRESHOLD" =~ ^[0-9]+$ ]] || scanner_failed "RISK_ABORT_THRESHOLD must be a non-negative integer"

  require_command curl
  require_command git
  require_command jq

  git rev-parse --is-inside-work-tree >/dev/null 2>&1 || scanner_failed "current directory is not inside a git worktree"

  collect_package_names
  collect_package_version
  pkgbuild_content="$(read_file_or_empty PKGBUILD)"
  add_user_message "Current PKGBUILD" "$pkgbuild_content"
  collect_pkgbuild_history
  collect_worktree_diff
  collect_authors
  collect_install_scripts

  if ! response_json="$(load_cached_response)"; then
    request_json="$(build_request_json)" || scanner_failed "failed to build OpenAI request"
    response_json="$(call_openai "$request_json")"
  fi
  verdict_json="$(extract_verdict_json "$response_json")"
  store_cached_response "$response_json"
  evaluate_verdict "$verdict_json"

  exec "$MAKEPKG_BIN" "$@"
}

main "$@"
