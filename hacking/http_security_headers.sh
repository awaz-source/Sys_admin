#!/usr/bin/env bash
# Assess common HTTP security headers on one authorized web target.
#
# Usage:
#   ./http_security_headers.sh https://example.com
#   ./http_security_headers.sh -t 15 -o header-report.txt https://lab.example
#
# Options:
#   -t SECONDS   connection and transfer timeout (default: 10)
#   -o FILE      save the report to FILE instead of standard output
#   -h           show help
#
# This performs one normal HTTP request and follows redirects. Use it only
# against applications you own or are explicitly authorized to test.

set -euo pipefail

timeout=10
output_file=""

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts ":t:o:h" option; do
  case "$option" in
    t) timeout=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h)
      usage
      exit 0
      ;;
    :)
      printf 'Error: -%s requires a value.\n' "$OPTARG" >&2
      exit 2
      ;;
    \?)
      printf 'Error: unknown option -%s.\n' "$OPTARG" >&2
      exit 2
      ;;
  esac
done
shift $((OPTIND - 1))

if (( $# != 1 )); then
  printf 'Error: provide exactly one HTTP or HTTPS URL.\n' >&2
  usage >&2
  exit 2
fi

target=$1
if [[ ! $target =~ ^https?:// ]]; then
  printf 'Error: target must begin with http:// or https://.\n' >&2
  exit 2
fi

if ! [[ $timeout =~ ^[1-9][0-9]*$ ]]; then
  printf 'Error: timeout must be a positive integer.\n' >&2
  exit 2
fi

if ! command -v curl >/dev/null 2>&1; then
  printf 'Error: curl is required.\n' >&2
  exit 2
fi

headers_file=$(mktemp)
final_headers_file=$(mktemp)
metadata_file=$(mktemp)
report_file=$(mktemp)
trap 'rm -f "$headers_file" "$final_headers_file" "$metadata_file" "$report_file"' EXIT

if ! curl \
  --silent \
  --show-error \
  --location \
  --max-time "$timeout" \
  --user-agent "SysAdmin-Security-Header-Check/1.0" \
  --output /dev/null \
  --dump-header "$headers_file" \
  --write-out '%{url_effective}\n%{http_code}\n' \
  "$target" >"$metadata_file"; then
  printf 'Error: request failed for %s.\n' "$target" >&2
  exit 1
fi

# Keep only the final response block so redirect responses do not create
# false positives. Removing carriage returns also normalizes HTTP/1.x output.
tr -d '\r' <"$headers_file" |
  awk 'BEGIN { RS="\n\n" } /^HTTP\// { final=$0 } END { print final }' \
    >"$final_headers_file"

effective_url=$(sed -n '1p' "$metadata_file")
status_code=$(sed -n '2p' "$metadata_file")

header_value() {
  local header_name=$1
  awk -F ': *' -v name="$header_name" '
    tolower($1) == tolower(name) {
      sub(/^[^:]+:[[:space:]]*/, "", $0)
      print
      exit
    }
  ' "$final_headers_file"
}

check_header() {
  local header_name=$1
  local purpose=$2
  local value
  value=$(header_value "$header_name")

  if [[ -n $value ]]; then
    printf '[PRESENT] %s: %s\n' "$header_name" "$value"
  else
    printf '[MISSING] %s — %s\n' "$header_name" "$purpose"
    missing_count=$((missing_count + 1))
  fi
}

missing_count=0
{
  printf 'HTTP SECURITY HEADER REPORT\n'
  printf 'Target: %s\n' "$target"
  printf 'Final URL: %s\n' "$effective_url"
  printf 'HTTP status: %s\n' "$status_code"
  printf 'Checked: %s\n\n' "$(date --iso-8601=seconds 2>/dev/null || date)"

  check_header "Content-Security-Policy" \
    "reduces script injection and content-loading risk"
  check_header "X-Content-Type-Options" \
    "prevents MIME-type sniffing when set to nosniff"
  check_header "Referrer-Policy" \
    "controls referrer information sent to other sites"
  check_header "Permissions-Policy" \
    "limits access to browser features"

  frame_options=$(header_value "X-Frame-Options")
  content_policy=$(header_value "Content-Security-Policy")
  if [[ -n $frame_options || $content_policy == *"frame-ancestors"* ]]; then
    printf '[PRESENT] Clickjacking control: %s\n' \
      "${frame_options:-Content-Security-Policy frame-ancestors}"
  else
    printf '[MISSING] Clickjacking control — set X-Frame-Options or CSP frame-ancestors\n'
    missing_count=$((missing_count + 1))
  fi

  if [[ $effective_url == https://* ]]; then
    check_header "Strict-Transport-Security" \
      "instructs browsers to continue using HTTPS"
  else
    printf '[INFO] Strict-Transport-Security was not scored because the final URL is HTTP.\n'
  fi

  printf '\nMissing recommended controls: %d\n' "$missing_count"
  printf 'Review each result in the context of the application before remediation.\n'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 "$report_file" "$output_file"
  printf 'Report written to %s\n' "$output_file"
else
  cat "$report_file"
fi
