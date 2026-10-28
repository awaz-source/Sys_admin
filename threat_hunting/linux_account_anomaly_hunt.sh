#!/usr/bin/env bash
# Read-only hunt for suspicious Linux account and home-directory conditions.
#
# Usage:
#   sudo ./linux_account_anomaly_hunt.sh
#   ./linux_account_anomaly_hunt.sh -r /mnt/forensic-image -o account-hunt.txt
#   ./linux_account_anomaly_hunt.sh -u 499
#
# Exit codes: 0 report completed, 1 findings detected, 2 usage/input error.

set -uo pipefail
umask 077

root="/"
system_uid_max=999
output=""

usage() {
  cat <<'USAGE'
Usage: linux_account_anomaly_hunt.sh [-r ROOT] [-u UID_MAX] [-o REPORT]

Options:
  -r ROOT     Live root or offline mounted Linux root (default: /)
  -u UID_MAX  Highest UID treated as a system account (default: 999)
  -o REPORT   Write the report to this file (permissions are forced to 600)
  -h          Show this help

The script is read-only. Run with sudo on a live host to include /etc/shadow.
Review findings in context: service accounts and shared administrative groups
can be legitimate when they are documented and expected.
USAGE
}

while getopts ":r:u:o:h" option; do
  case "$option" in
    r) root=$OPTARG ;;
    u) system_uid_max=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! $system_uid_max =~ ^[0-9]+$ ]]; then
  printf 'UID_MAX must be a non-negative integer.\n' >&2
  exit 2
fi

root=${root%/}
[[ -n $root ]] || root="/"
passwd_file="${root%/}/etc/passwd"
group_file="${root%/}/etc/group"
shadow_file="${root%/}/etc/shadow"

for required in "$passwd_file" "$group_file"; do
  if [[ ! -r $required ]]; then
    printf 'Required file is not readable: %s\n' "$required" >&2
    exit 2
  fi
done

tmp_report=$(mktemp)
trap 'rm -f "$tmp_report"' EXIT
findings=0

section() {
  printf '\n== %s ==\n' "$1" >>"$tmp_report"
}

record_awk_findings() {
  local title=$1 program=$2 source=$3 result
  section "$title"
  result=$(awk -F: "$program" "$source")
  if [[ -n $result ]]; then
    printf '%s\n' "$result" >>"$tmp_report"
    findings=$((findings + $(printf '%s\n' "$result" | awk 'END {print NR}')))
  else
    printf 'None found.\n' >>"$tmp_report"
  fi
}

{
  printf 'Linux Account Anomaly Hunt\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Inspected root: %s\n' "$root"
  printf 'Accounts: %s | Groups: %s\n' \
    "$(awk -F: 'NF >= 7 {n++} END {print n+0}' "$passwd_file")" \
    "$(awk -F: 'NF >= 4 {n++} END {print n+0}' "$group_file")"
  printf 'System UID ceiling: %s\n' "$system_uid_max"
} >"$tmp_report"

record_awk_findings "Additional UID 0 accounts" \
  '$3 == 0 && $1 != "root" {printf "[HIGH] user=%s uid=0 shell=%s home=%s\n", $1, $7, $6}' \
  "$passwd_file"

record_awk_findings "Duplicate numeric UIDs" \
  '{count[$3]++; names[$3]=(names[$3] ? names[$3] "," : "") $1} END {for (uid in count) if (count[uid] > 1) printf "[HIGH] uid=%s users=%s\n", uid, names[uid]}' \
  "$passwd_file"

record_awk_findings "System accounts with interactive shells" \
  '$3 > 0 && $3 <= '"$system_uid_max"' && $7 !~ /(nologin|false|sync|shutdown|halt)$/ {printf "[MEDIUM] user=%s uid=%s shell=%s\n", $1, $3, $7}' \
  "$passwd_file"

record_awk_findings "Members of high-impact groups" \
  '$1 ~ /^(sudo|wheel|adm|docker|lxd|libvirt)$/ && $4 != "" {printf "[REVIEW] group=%s members=%s\n", $1, $4}' \
  "$group_file"

section "Password database checks"
if [[ -r $shadow_file ]]; then
  shadow_findings=$(awk -F: '
    $2 == "" {printf "[CRITICAL] user=%s has an empty password field\n", $1; next}
    $2 !~ /^(!|\*)/ && ($5 == "" || $5 == -1 || $5 > 365) {
      printf "[REVIEW] user=%s password_max_days=%s\n", $1, ($5 == "" ? "unset" : $5)
    }
  ' "$shadow_file")
  if [[ -n $shadow_findings ]]; then
    printf '%s\n' "$shadow_findings" >>"$tmp_report"
    findings=$((findings + $(printf '%s\n' "$shadow_findings" | awk 'END {print NR}')))
  else
    printf 'None found.\n' >>"$tmp_report"
  fi
else
  printf 'Not inspected: %s is not readable. Re-run with sudo for full coverage.\n' "$shadow_file" >>"$tmp_report"
fi

section "Home directory checks"
home_findings=""
while IFS=: read -r user _ uid _ _ home shell; do
  [[ -n $user && -n $uid && -n $home ]] || continue
  [[ $home != /nonexistent && $home != /dev/null ]] || continue
  [[ $shell != */nologin && $shell != */false ]] || continue

  if [[ $root == / ]]; then
    inspected_home=$home
  else
    inspected_home="${root%/}$home"
  fi

  if [[ ! -d $inspected_home ]]; then
    home_findings+="[MEDIUM] user=$user home=$home is missing\n"
    continue
  fi

  read -r owner mode < <(stat -c '%u %a' "$inspected_home")
  if [[ $owner != "$uid" ]]; then
    home_findings+="[MEDIUM] user=$user home=$home owner_uid=$owner expected_uid=$uid\n"
  fi
  group_digit=${mode: -2:1}
  other_digit=${mode: -1}
  if [[ $group_digit =~ [2367] || $other_digit =~ [2367] ]]; then
    home_findings+="[HIGH] user=$user home=$home mode=$mode is group/world writable\n"
  fi
done <"$passwd_file"

if [[ -n $home_findings ]]; then
  printf '%b' "$home_findings" >>"$tmp_report"
  findings=$((findings + $(printf '%b' "$home_findings" | awk 'END {print NR}')))
else
  printf 'None found.\n' >>"$tmp_report"
fi

{
  section "Summary"
  printf 'Findings requiring review: %s\n' "$findings"
  printf 'Suggested follow-up: confirm each account and group membership against an approved identity source; investigate unexplained changes in authentication logs.\n'
} >>"$tmp_report"

if [[ -n $output ]]; then
  cp "$tmp_report" "$output"
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

(( findings == 0 )) && exit 0
exit 1
