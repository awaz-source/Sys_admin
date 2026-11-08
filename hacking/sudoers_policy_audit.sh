#!/usr/bin/env bash
# Audit sudoers policy files for high-risk privilege grants and unsafe permissions.
# Authorized defensive use only. This script is read-only and executes no sudo rules.
#
# Examples:
#   sudo ./sudoers_policy_audit.sh
#   ./sudoers_policy_audit.sh -r /mnt/offline-host
#   sudo ./sudoers_policy_audit.sh -o sudoers-audit.txt
#
# Exit codes: 0 audit completed, 2 invalid input or collection error.

set -uo pipefail
umask 077

root="/"
output=""

usage() {
  cat <<'USAGE'
Usage: sudoers_policy_audit.sh [-r ROOT] [-o REPORT]

Options:
  -r ROOT    Filesystem root to inspect (default: /)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

The script reviews /etc/sudoers and regular files in /etc/sudoers.d. It flags
unsafe file permissions, non-root ownership, broad NOPASSWD grants, disabled
authentication, SETENV, command wildcards, and commands commonly capable of
shell escapes. Findings require analyst review and are not proof of compromise.
USAGE
}

while getopts ":r:o:h" option; do
  case "$option" in
    r) root=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -d $root ]]; then
  printf 'Filesystem root is not a directory: %s\n' "$root" >&2
  exit 2
fi
root=${root%/}
[[ -n $root ]] || root=/

tmp_files=$(mktemp)
tmp_rules=$(mktemp)
tmp_findings=$(mktemp)
tmp_logical=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_files" "$tmp_rules" "$tmp_findings" "$tmp_logical" "$tmp_report"' EXIT

main_file="${root}/etc/sudoers"
dropin_dir="${root}/etc/sudoers.d"
[[ -f $main_file || -L $main_file ]] && printf '%s\0' "$main_file" >>"$tmp_files"
if [[ -d $dropin_dir ]]; then
  find "$dropin_dir" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) -print0 \
    2>/dev/null >>"$tmp_files" || {
      printf 'Unable to inspect sudoers drop-in directory: %s\n' "$dropin_dir" >&2
      exit 2
    }
fi

file_count=0
rule_count=0
finding_count=0

add_finding() {
  local severity=$1 location=$2 reason=$3
  printf '%s | %s | %s\n' "$severity" "$location" "$reason" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
}

while IFS= read -r -d '' path; do
  file_count=$((file_count + 1))
  display_path=${path#"$root"}
  [[ $display_path == /* ]] || display_path="/$display_path"

  if [[ -L $path ]]; then
    target=$(readlink -- "$path" 2>/dev/null || printf unreadable)
    add_finding MEDIUM "$display_path" "policy file is a symlink to $target"
  fi

  metadata=$(stat -Lc '%a|%U|%G' -- "$path" 2>/dev/null) || {
    add_finding HIGH "$display_path" 'unable to read file metadata'
    continue
  }
  IFS='|' read -r mode owner group <<<"$metadata"
  permission_value=$((8#$mode))

  [[ $owner == root ]] || add_finding HIGH "$display_path" "policy file owned by $owner"
  if (( (permission_value & 0033) != 0 )); then
    add_finding HIGH "$display_path" "unsafe sudoers permissions ($mode, owner $owner, group $group)"
  elif (( (permission_value & 0004) != 0 )); then
    add_finding MEDIUM "$display_path" "sudoers policy is world-readable ($mode)"
  fi

  if [[ ! -r $path ]]; then
    add_finding HIGH "$display_path" 'policy content is unreadable by the current user'
    continue
  fi

  awk '
    {
      sub(/\r$/, "")
      if (continued) buffer = buffer $0; else { buffer = $0; start = NR }
      if (buffer ~ /\\[[:space:]]*$/) {
        sub(/\\[[:space:]]*$/, " ", buffer)
        continued = 1
        next
      }
      print start "|" buffer
      buffer = ""
      continued = 0
    }
    END { if (continued && buffer != "") print start "|" buffer }
  ' "$path" >"$tmp_logical"

  while IFS='|' read -r line_number line; do
    trimmed=${line#"${line%%[![:space:]]*}"}
    [[ -n $trimmed && ${trimmed:0:1} != '#' ]] || continue
    rule_count=$((rule_count + 1))
    printf '%s:%s | %s\n' "$display_path" "$line_number" "$line" >>"$tmp_rules"
    location="$display_path:$line_number"

    if grep -Eqi 'NOPASSWD[[:space:]]*:[[:space:]]*ALL([[:space:]]|$|,)' <<<"$line"; then
      add_finding CRITICAL "$location" 'passwordless execution of ALL commands'
    elif grep -Eqi 'NOPASSWD[[:space:]]*:' <<<"$line"; then
      add_finding MEDIUM "$location" 'passwordless command grant; verify least privilege'
    fi

    if grep -Eqi 'Defaults([^#]*)!authenticate' <<<"$line"; then
      add_finding CRITICAL "$location" 'sudo authentication is disabled'
    fi
    if grep -Eqi '(^|[[:space:],:])SETENV([[:space:],:]|$)' <<<"$line"; then
      add_finding HIGH "$location" 'SETENV can permit security-sensitive environment changes'
    fi
    if grep -Eq '[?*]' <<<"$line"; then
      add_finding HIGH "$location" 'command path or argument contains a wildcard'
    fi
    if grep -Eqi '(^|[[:space:],=/])(ba)?sh([[:space:],]|$)|/(vi|vim|nano|less|more|man|awk|perl|python([0-9.]*)?|ruby|lua|env|find|tar|rsync|tee|cp|mv|systemctl|service|journalctl|dnf|yum|apt(-get)?)([[:space:],]|$)' <<<"$line"; then
      add_finding HIGH "$location" 'grant includes a shell or commonly shell-escape-capable binary'
    fi
  done <"$tmp_logical"
done <"$tmp_files"

{
  printf 'Sudoers Policy Security Audit\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Filesystem root: %s\n' "$root"
  printf 'Policy files inspected: %d\n' "$file_count"
  printf 'Active policy lines: %d\n' "$rule_count"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Active policy lines ==\n'
  if (( rule_count == 0 )); then
    printf 'No active sudoers policy lines were readable in the inspected locations.\n'
  else
    cat "$tmp_rules"
  fi

  printf '\n== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No configured risk patterns were identified.\n'
  else
    sort -t '|' -k1,1 -k2,2 "$tmp_findings"
  fi

  printf '\n== Validation guidance ==\n'
  printf 'Confirm each grant against an approved least-privilege requirement.\n'
  printf 'Use visudo -c against live policy before making changes; this audit never edits policy.\n'
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

exit 0
