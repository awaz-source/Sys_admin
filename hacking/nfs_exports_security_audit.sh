#!/usr/bin/env bash
# Read-only security audit for Linux NFS exports configuration.
# Intended for authorized administration, lab validation, and defensive review.
#
# Examples:
#   sudo ./nfs_exports_security_audit.sh
#   ./nfs_exports_security_audit.sh -f ./exports.lab
#   ./nfs_exports_security_audit.sh -f /etc/exports -o nfs-audit.txt
#
# Exit codes: 0 no risky settings found, 1 findings require review,
# 2 invalid arguments or unreadable input.

set -uo pipefail
umask 077

exports_file=/etc/exports
output=""

usage() {
  cat <<'USAGE'
Usage: nfs_exports_security_audit.sh [-f EXPORTS_FILE] [-o REPORT]

Options:
  -f FILE    Exports configuration to inspect (default: /etc/exports)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

The script does not contact NFS clients or modify exports. It highlights broad
client scopes, writable exports, no_root_squash, insecure source-port handling,
and root-equivalent anonymous mappings. Confirm findings against the intended
trust boundary before changing production configuration.
USAGE
}

while getopts ":f:o:h" option; do
  case "$option" in
    f) exports_file=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -r $exports_file ]]; then
  printf 'Exports file is not readable: %s\n' "$exports_file" >&2
  exit 2
fi

tmp_normalized=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_normalized" "$tmp_report"' EXIT

# Remove comments and join lines ending in a backslash. This keeps the audit
# deterministic without invoking exportfs or changing the kernel export table.
awk '
  {
    sub(/[[:space:]]*#.*/, "")
    if ($0 ~ /\\[[:space:]]*$/) {
      sub(/\\[[:space:]]*$/, "", $0)
      pending = pending $0 " "
      next
    }
    line = pending $0
    pending = ""
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", line)
    if (line != "") print line
  }
  END {
    gsub(/^[[:space:]]+|[[:space:]]+$/, "", pending)
    if (pending != "") print pending
  }
' "$exports_file" >"$tmp_normalized"

findings=0
exports_count=0
client_count=0

{
  printf 'NFS Exports Security Audit\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Source: %s\n' "$exports_file"
  printf '\n== Export review ==\n'
} >"$tmp_report"

while IFS= read -r line; do
  read -ra fields <<<"$line"
  export_path=${fields[0]:-}
  exports_count=$((exports_count + 1))

  if [[ $export_path != /* ]]; then
    printf '[HIGH] invalid_or_relative_export=%s\n' "$export_path" >>"$tmp_report"
    findings=$((findings + 1))
  fi

  if (( ${#fields[@]} < 2 )); then
    printf '[HIGH] export=%s has no client specification\n' "$export_path" >>"$tmp_report"
    findings=$((findings + 1))
    continue
  fi

  for ((index = 1; index < ${#fields[@]}; index++)); do
    specification=${fields[$index]}
    client_count=$((client_count + 1))

    if [[ $specification =~ ^([^()]*)[(](.*)[)]$ ]]; then
      client=${BASH_REMATCH[1]}
      options=${BASH_REMATCH[2]}
    elif [[ $specification != *'('* && $specification != *')'* ]]; then
      client=$specification
      options=""
    else
      printf '[HIGH] export=%s malformed_client_spec=%s\n' \
        "$export_path" "$specification" >>"$tmp_report"
      findings=$((findings + 1))
      continue
    fi

    printf 'export=%s client=%s options=%s\n' \
      "$export_path" "$client" "${options:-defaults}" >>"$tmp_report"

    case "$client" in
      '*'|'0.0.0.0/0'|'::/0')
        printf '  [HIGH] Export is available to an unrestricted client scope.\n' >>"$tmp_report"
        findings=$((findings + 1))
        ;;
    esac

    option_list=",${options//[[:space:]]/},"
    if [[ $option_list == *,no_root_squash,* ]]; then
      printf '  [CRITICAL] no_root_squash permits remote root identity.\n' >>"$tmp_report"
      findings=$((findings + 1))
    fi
    if [[ $option_list == *,insecure,* ]]; then
      printf '  [HIGH] insecure accepts requests from non-privileged source ports.\n' >>"$tmp_report"
      findings=$((findings + 1))
    fi
    if [[ $option_list == *,rw,* ]]; then
      printf '  [REVIEW] Client has write access to the export.\n' >>"$tmp_report"
      findings=$((findings + 1))
    fi
    if [[ $option_list == *,anonuid=0,* || $option_list == *,anongid=0,* ]]; then
      printf '  [CRITICAL] Anonymous NFS identity maps to UID or GID 0.\n' >>"$tmp_report"
      findings=$((findings + 1))
    fi
  done
done <"$tmp_normalized"

{
  printf '\n== Summary ==\n'
  printf 'Exports inspected: %d\n' "$exports_count"
  printf 'Client specifications inspected: %d\n' "$client_count"
  printf 'Findings requiring review: %d\n' "$findings"
  if (( exports_count == 0 )); then
    printf 'No active export entries were present in the file.\n'
  elif (( findings == 0 )); then
    printf 'No configured settings matched the audited risk conditions.\n'
  else
    printf 'Validate client scopes and least-privilege requirements before remediation.\n'
  fi
} >>"$tmp_report"

if [[ -n $output ]]; then
  cp -- "$tmp_report" "$output"
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

(( findings == 0 )) && exit 0
exit 1
