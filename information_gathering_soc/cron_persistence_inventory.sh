#!/usr/bin/env bash
# Inventory Linux cron persistence and highlight entries that deserve SOC review.
# Read-only: this script does not change cron files, permissions, or services.
#
# Examples:
#   sudo ./cron_persistence_inventory.sh
#   ./cron_persistence_inventory.sh -r /mnt/forensic-image
#   sudo ./cron_persistence_inventory.sh -o cron-inventory.txt
#
# Exit codes: 0 completed successfully, 2 invalid input or collection failure.

set -uo pipefail
umask 077

root="/"
output=""

usage() {
  cat <<'USAGE'
Usage: cron_persistence_inventory.sh [-r ROOT] [-o REPORT]

Options:
  -r ROOT    Filesystem root to inspect (default: /)
  -o REPORT  Save output with permissions set to 600
  -h         Show this help

The report inventories system cron files, periodic cron directories, anacron,
and common per-user crontab spool locations. Findings flag unsafe permissions,
unexpected ownership, hidden files, symlinks, and command patterns commonly
seen in persistence or download-and-execute activity. Findings require analyst
review and are not proof of compromise.
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
tmp_entries=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_files" "$tmp_entries" "$tmp_findings" "$tmp_report"' EXIT

declare -a scan_paths=(
  /etc/crontab
  /etc/anacrontab
  /etc/cron.d
  /etc/cron.hourly
  /etc/cron.daily
  /etc/cron.weekly
  /etc/cron.monthly
  /var/spool/cron
  /var/spool/cron/crontabs
)

for relative in "${scan_paths[@]}"; do
  candidate="${root}${relative}"
  if [[ -f $candidate || -L $candidate ]]; then
    printf '%s\0' "$candidate" >>"$tmp_files"
  elif [[ -d $candidate ]]; then
    find "$candidate" -mindepth 1 -maxdepth 1 \( -type f -o -type l \) -print0 \
      2>/dev/null >>"$tmp_files" || {
        printf 'Unable to inspect cron directory: %s\n' "$candidate" >&2
        exit 2
      }
  fi
done

file_count=0
entry_count=0
finding_count=0

add_finding() {
  local severity=$1 path=$2 reason=$3
  printf '%s | %s | %s\n' "$severity" "$path" "$reason" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
}

while IFS= read -r -d '' path; do
  file_count=$((file_count + 1))
  display_path=${path#"$root"}
  [[ $display_path == /* ]] || display_path="/$display_path"

  if [[ -L $path ]]; then
    target=$(readlink -- "$path" 2>/dev/null || printf unreadable)
    add_finding MEDIUM "$display_path" "symlink target: $target"
  fi

  metadata=$(stat -Lc '%a|%U|%G' -- "$path" 2>/dev/null) || {
    add_finding HIGH "$display_path" 'unable to read file metadata'
    continue
  }
  IFS='|' read -r mode owner group <<<"$metadata"
  permission_value=$((8#$mode))

  if (( (permission_value & 0002) != 0 )); then
    add_finding HIGH "$display_path" "world-writable permissions ($mode)"
  elif (( (permission_value & 0020) != 0 )); then
    add_finding MEDIUM "$display_path" "group-writable permissions ($mode, group $group)"
  fi

  case "$display_path" in
    /etc/*)
      [[ $owner == root ]] || add_finding HIGH "$display_path" "system cron file owned by $owner"
      ;;
  esac

  basename_value=${display_path##*/}
  [[ $basename_value != .* ]] || add_finding MEDIUM "$display_path" 'hidden cron file'

  if [[ ! -r $path ]]; then
    add_finding MEDIUM "$display_path" 'content is not readable by the current user'
    continue
  fi

  line_number=0
  while IFS= read -r line || [[ -n $line ]]; do
    line_number=$((line_number + 1))
    trimmed=${line#"${line%%[![:space:]]*}"}
    [[ -n $trimmed && ${trimmed:0:1} != '#' ]] || continue
    [[ ! $trimmed =~ ^[[:alpha:]_][[:alnum:]_]*= ]] || continue
    entry_count=$((entry_count + 1))
    printf '%s:%d | %s\n' "$display_path" "$line_number" "$line" >>"$tmp_entries"

    if grep -Eqi '(^|[[:space:];|&])(/tmp|/var/tmp|/dev/shm)(/|[[:space:];|&]|$)' <<<"$line"; then
      add_finding HIGH "$display_path:$line_number" 'command references a temporary execution path'
    fi
    if grep -Eqi '(curl|wget).*(\||;|&&)[[:space:]]*(ba)?sh|[|][[:space:]]*(ba)?sh' <<<"$line"; then
      add_finding HIGH "$display_path:$line_number" 'possible download-and-execute pipeline'
    fi
    if grep -Eqi 'base64[[:space:]].*(-d|--decode)|(^|[[:space:];|&])(nc|ncat|socat)[[:space:]]' <<<"$line"; then
      add_finding MEDIUM "$display_path:$line_number" 'encoded payload or network relay command pattern'
    fi
    if grep -Eqi 'chmod[[:space:]]+([ugo+]*s|[0-7]*[46][0-7]{2})' <<<"$line"; then
      add_finding HIGH "$display_path:$line_number" 'command may set SUID or SGID permissions'
    fi
  done <"$path"
done <"$tmp_files"

{
  printf 'Cron Persistence Inventory\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Filesystem root: %s\n' "$root"
  printf 'Files inspected: %d\n' "$file_count"
  printf 'Active entries: %d\n' "$entry_count"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Scheduled entries ==\n'
  if (( entry_count == 0 )); then
    printf 'No active cron or anacron entries found in inspected locations.\n'
  else
    cat "$tmp_entries"
  fi

  printf '\n== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No configured risk patterns were identified.\n'
  else
    sort -t '|' -k1,1 -k2,2 "$tmp_findings"
  fi

  printf '\n== Analyst notes ==\n'
  printf 'Compare entries with change records, package ownership, and approved baselines.\n'
  printf 'Also review systemd timers, at jobs, shell profiles, and container schedulers separately.\n'
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
