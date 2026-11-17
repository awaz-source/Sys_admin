#!/usr/bin/env bash
# Summarize package installation, upgrade, downgrade, and removal history.
# Read-only: package databases and log files are never modified.
#
# Examples:
#   sudo ./package_change_report.sh
#   ./package_change_report.sh -f /var/log/apt/history.log
#   ./package_change_report.sh -f /var/log/dnf.log -f /var/log/dnf.rpm.log
#   sudo ./package_change_report.sh -l 5000 -o package-changes.txt
#
# Exit codes: 0 report generated, 2 input or collection error.

set -uo pipefail
umask 077

line_limit=10000
output=""
declare -a log_files=()

usage() {
  cat <<'USAGE'
Usage: package_change_report.sh [-f LOG]... [-l LINES] [-o REPORT]

Options:
  -f LOG     Package-manager log to parse; may be repeated
  -l LINES   Read at most this many trailing lines per log (default: 10000)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

Without -f, the script uses readable APT, DNF, and YUM history logs from
/var/log. Plain-text and .gz files are supported. The report groups APT
transaction lines and RPM-family package actions into a normalized timeline.
USAGE
}

while getopts ":f:l:o:h" option; do
  case "$option" in
    f) log_files+=("$OPTARG") ;;
    l) line_limit=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! $line_limit =~ ^[1-9][0-9]*$ ]]; then
  printf 'LINES must be a positive integer: %s\n' "$line_limit" >&2
  exit 2
fi

if (( ${#log_files[@]} == 0 )); then
  for candidate in \
    /var/log/apt/history.log /var/log/apt/history.log.*.gz \
    /var/log/dnf.log /var/log/dnf.log-*.gz \
    /var/log/dnf.rpm.log /var/log/dnf.rpm.log-*.gz \
    /var/log/yum.log /var/log/yum.log-*.gz; do
    [[ -r $candidate ]] && log_files+=("$candidate")
  done
fi

if (( ${#log_files[@]} == 0 )); then
  printf 'No readable package-manager logs were found. Use -f to specify a log.\n' >&2
  exit 2
fi

for log_file in "${log_files[@]}"; do
  if [[ ! -f $log_file || ! -r $log_file ]]; then
    printf 'Log is not a readable regular file: %s\n' "$log_file" >&2
    exit 2
  fi
done

tmp_events=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_events" "$tmp_report"' EXIT

read_log() {
  local path=$1
  if [[ $path == *.gz ]]; then
    command -v gzip >/dev/null 2>&1 || {
      printf 'gzip is required to read: %s\n' "$path" >&2
      return 2
    }
    gzip -cd -- "$path"
  else
    cat -- "$path"
  fi
}

for log_file in "${log_files[@]}"; do
  if ! read_log "$log_file" | tail -n "$line_limit" | awk -v source="$log_file" '
    BEGIN { apt_date = "unknown" }
    /^Start-Date:[[:space:]]*/ {
      apt_date = $0
      sub(/^Start-Date:[[:space:]]*/, "", apt_date)
      next
    }
    /^(Install|Upgrade|Downgrade|Remove|Purge):[[:space:]]*/ {
      action = $1
      sub(/:$/, "", action)
      detail = $0
      sub(/^[^:]+:[[:space:]]*/, "", detail)
      gsub(/\t/, " ", detail)
      printf "%s\t%s\t%s\t%s\n", apt_date, toupper(action), source, detail
      next
    }
    {
      line = $0
      if (line ~ /(Installed|Upgraded|Downgraded|Removed|Erased):[[:space:]]+/) {
        timestamp = line
        sub(/[[:space:]]+(INFO|DEBUG|NOTICE)[[:space:]].*$/, "", timestamp)
        if (timestamp == line) {
          split(line, fields, /[[:space:]]+/)
          timestamp = fields[1] " " fields[2] " " fields[3]
        }
        action = line
        sub(/^.*(Installed|Upgraded|Downgraded|Removed|Erased):[[:space:]]*/, "", action)
        match(line, /(Installed|Upgraded|Downgraded|Removed|Erased):/)
        verb = substr(line, RSTART, RLENGTH - 1)
        if (verb == "Erased") verb = "Removed"
        gsub(/\t/, " ", action)
        printf "%s\t%s\t%s\t%s\n", timestamp, toupper(verb), source, action
      }
    }
  ' >>"$tmp_events"; then
    printf 'Unable to parse package-manager log: %s\n' "$log_file" >&2
    exit 2
  fi
done

event_count=$(wc -l <"$tmp_events")
install_count=$(awk -F'\t' '$2 == "INSTALL" || $2 == "INSTALLED" {count++} END {print count+0}' "$tmp_events")
upgrade_count=$(awk -F'\t' '$2 == "UPGRADE" || $2 == "UPGRADED" {count++} END {print count+0}' "$tmp_events")
downgrade_count=$(awk -F'\t' '$2 == "DOWNGRADE" || $2 == "DOWNGRADED" {count++} END {print count+0}' "$tmp_events")
remove_count=$(awk -F'\t' '$2 == "REMOVE" || $2 == "REMOVED" || $2 == "PURGE" {count++} END {print count+0}' "$tmp_events")

{
  printf 'Package Change Report\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Logs parsed: %d\n' "${#log_files[@]}"
  printf 'Transaction events: %d\n' "$event_count"
  printf 'Installs: %d | Upgrades: %d | Downgrades: %d | Removals/Purges: %d\n' \
    "$install_count" "$upgrade_count" "$downgrade_count" "$remove_count"

  printf '\n== Normalized package change timeline ==\n'
  if (( event_count == 0 )); then
    printf 'No recognized package changes were found in the selected log range.\n'
  else
    printf 'DATE | ACTION | SOURCE | PACKAGE DETAILS\n'
    sort -t $'\t' -k1,1 -k2,2 "$tmp_events" | tr '\t' '|'
  fi

  printf '\n== Review guidance ==\n'
  printf 'Correlate unexpected changes with approved maintenance, sudo, and authentication logs.\n'
  printf 'APT lines may list several packages in one transaction event; counts are event-line totals.\n'
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
