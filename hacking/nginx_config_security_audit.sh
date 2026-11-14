#!/usr/bin/env bash
# Audit local Nginx configuration files for defensive security review.
# Authorized defensive use only. This script is read-only and does not reload Nginx.
#
# Examples:
#   sudo ./nginx_config_security_audit.sh
#   ./nginx_config_security_audit.sh -d /mnt/server/etc/nginx
#   sudo ./nginx_config_security_audit.sh -o nginx-audit.txt
#
# Exit codes: 0 no findings, 1 review findings present, 2 input/collection error.

set -uo pipefail
umask 077

config_dir=/etc/nginx
output=""

usage() {
  cat <<'USAGE'
Usage: nginx_config_security_audit.sh [-d CONFIG_DIR] [-o REPORT]

Options:
  -d DIR     Nginx configuration directory (default: /etc/nginx)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

The script recursively inspects nginx.conf and *.conf files. It reviews file
ownership and permissions, server token exposure, directory listing, legacy
TLS, upstream certificate verification, broad CORS, plaintext proxy upstreams,
and sensitive document roots. Findings are heuristic and require context.
USAGE
}

while getopts ":d:o:h" option; do
  case "$option" in
    d) config_dir=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -d $config_dir ]]; then
  printf 'Nginx configuration directory was not found: %s\n' "$config_dir" >&2
  exit 2
fi

tmp_files=$(mktemp)
tmp_directives=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_files" "$tmp_directives" "$tmp_findings" "$tmp_report"' EXIT

find "$config_dir" -type f \( -name nginx.conf -o -name '*.conf' \) -print0 \
  2>/dev/null >"$tmp_files" || {
    printf 'Unable to enumerate Nginx configuration files: %s\n' "$config_dir" >&2
    exit 2
  }

file_count=0
directive_count=0
finding_count=0

add_finding() {
  local severity=$1 location=$2 reason=$3
  printf '%s\t%s\t%s\n' "$severity" "$location" "$reason" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
}

while IFS= read -r -d '' path; do
  file_count=$((file_count + 1))
  display_path=${path#"$config_dir"}
  [[ $display_path == /* ]] || display_path="/$display_path"

  metadata=$(stat -Lc '%a|%U|%G' -- "$path" 2>/dev/null) || {
    add_finding HIGH "$display_path" 'unable to read file metadata'
    continue
  }
  IFS='|' read -r mode owner group <<<"$metadata"
  permission_value=$((8#$mode))
  [[ $owner == root ]] || add_finding MEDIUM "$display_path" "configuration owned by $owner"
  if (( (permission_value & 0022) != 0 )); then
    add_finding HIGH "$display_path" "configuration is group/world writable ($mode, group $group)"
  fi

  if [[ ! -r $path ]]; then
    add_finding HIGH "$display_path" 'configuration is unreadable by the current user'
    continue
  fi

  line_number=0
  while IFS= read -r line || [[ -n $line ]]; do
    line_number=$((line_number + 1))
    active=${line%%#*}
    active=${active#"${active%%[![:space:]]*}"}
    active=${active%"${active##*[![:space:]]}"}
    [[ -n $active ]] || continue
    directive_count=$((directive_count + 1))
    location="$display_path:$line_number"
    printf '%s\t%s\n' "$location" "$active" >>"$tmp_directives"

    if grep -Eqi '^server_tokens[[:space:]]+on[[:space:]]*;' <<<"$active"; then
      add_finding MEDIUM "$location" 'server_tokens explicitly exposes the Nginx version'
    fi
    if grep -Eqi '^autoindex[[:space:]]+on[[:space:]]*;' <<<"$active"; then
      add_finding HIGH "$location" 'directory listing is enabled'
    fi
    if grep -Eqi '^ssl_protocols[[:space:]]+([^;]*[[:space:]])?TLSv1(\.0)?([[:space:];]|$)|^ssl_protocols[[:space:]]+([^;]*[[:space:]])?TLSv1\.1([[:space:];]|$)' <<<"$active"; then
      add_finding HIGH "$location" 'legacy TLSv1.0 or TLSv1.1 is enabled'
    fi
    if grep -Eqi '^proxy_ssl_verify[[:space:]]+off[[:space:]]*;' <<<"$active"; then
      add_finding HIGH "$location" 'upstream TLS certificate verification is disabled'
    fi
    if grep -Eqi "^add_header[[:space:]]+Access-Control-Allow-Origin[[:space:]]+['\"]?\\*['\"]?([[:space:]]|;)" <<<"$active"; then
      add_finding MEDIUM "$location" 'CORS allows every origin'
    fi
    if grep -Eqi '^proxy_pass[[:space:]]+http://' <<<"$active" \
      && ! grep -Eqi '^proxy_pass[[:space:]]+http://(127\.0\.0\.1|localhost|\[::1\])([:/;]|$)' <<<"$active"; then
      add_finding MEDIUM "$location" 'proxy uses plaintext HTTP to a non-loopback upstream'
    fi
    if grep -Eqi '^(root|alias)[[:space:]]+/(etc|root|home|proc|sys|var/log)(/|[[:space:];])' <<<"$active"; then
      add_finding HIGH "$location" 'document root or alias references a sensitive filesystem path'
    fi
  done <"$path"
done <"$tmp_files"

if (( file_count == 0 )); then
  printf 'No nginx.conf or *.conf files were found under: %s\n' "$config_dir" >&2
  exit 2
fi

{
  printf 'Nginx Configuration Security Audit\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Configuration directory: %s\n' "$config_dir"
  printf 'Files inspected: %d\n' "$file_count"
  printf 'Active configuration lines: %d\n' "$directive_count"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Security-relevant directives ==\n'
  awk -F'\t' 'tolower($2) ~ /^(listen|server_name|server_tokens|autoindex|ssl_protocols|proxy_pass|proxy_ssl_verify|add_header|root|alias)[[:space:]]/ {print $1 " | " $2}' \
    "$tmp_directives"

  printf '\n== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No configured risk patterns were identified.\n'
  else
    sort -t $'\t' -k1,1 -k2,2 "$tmp_findings" \
      | awk -F'\t' '{print $1 " | " $2 " | " $3}'
  fi

  printf '\n== Validation guidance ==\n'
  printf 'Review findings within their http, server, and location contexts before changing them.\n'
  printf 'Validate any edits with nginx -t and use an approved rollback and reload procedure.\n'
} >"$tmp_report"

if [[ -n $output ]]; then
  cp -- "$tmp_report" "$output" || {
    printf 'Unable to write report: %s\n' "$output" >&2
    exit 2
  }
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

(( finding_count == 0 )) && exit 0
exit 1
