#!/usr/bin/env bash
# Report available Linux package updates without refreshing metadata or changing packages.
#
# Examples:
#   ./package_update_report.sh
#   ./package_update_report.sh -m dnf -n 50
#   ./package_update_report.sh -o package-updates.txt
#
# Exit codes: 0 no updates, 1 updates available, 2 collection/input error.

set -uo pipefail
umask 077

manager=auto
max_results=30
output=""

usage() {
  cat <<'USAGE'
Usage: package_update_report.sh [-m MANAGER] [-n COUNT] [-o REPORT]

Options:
  -m MANAGER  auto, dnf, yum, apt, or zypper (default: auto)
  -n COUNT    Maximum update rows shown in the report (default: 30)
  -o REPORT   Save the report with permissions set to 600
  -h          Show this help

The script uses currently available package metadata. It does not refresh
repositories or install packages, so run the normal metadata-refresh command
first when policy requires a current repository view.
USAGE
}

while getopts ":m:n:o:h" option; do
  case "$option" in
    m) manager=$OPTARG ;;
    n) max_results=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! $max_results =~ ^[1-9][0-9]*$ ]]; then
  printf 'COUNT must be a positive integer.\n' >&2
  exit 2
fi

case "$manager" in
  auto)
    for candidate in dnf yum apt zypper; do
      if command -v "$candidate" >/dev/null 2>&1; then
        manager=$candidate
        break
      fi
    done
    [[ $manager != auto ]] || {
      printf 'No supported package manager was found.\n' >&2
      exit 2
    }
    ;;
  dnf|yum|apt|zypper)
    command -v "$manager" >/dev/null 2>&1 || {
      printf 'Requested package manager was not found: %s\n' "$manager" >&2
      exit 2
    }
    ;;
  *)
    printf 'MANAGER must be auto, dnf, yum, apt, or zypper.\n' >&2
    exit 2
    ;;
esac

tmp_raw=$(mktemp)
tmp_updates=$(mktemp)
tmp_security=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_raw" "$tmp_updates" "$tmp_security" "$tmp_report"' EXIT

security_status=unavailable
collection_status=0

case "$manager" in
  dnf|yum)
    "$manager" -q check-update >"$tmp_raw" 2>/dev/null
    collection_status=$?
    if (( collection_status != 0 && collection_status != 100 )); then
      printf '%s check-update failed with status %d.\n' "$manager" "$collection_status" >&2
      exit 2
    fi
    awk 'NF >= 3 && $1 ~ /^[[:alnum:]_.+:-]+$/ && $2 ~ /^[0-9]/ {print}' \
      "$tmp_raw" >"$tmp_updates"

    if "$manager" -q updateinfo list --security --available >"$tmp_raw" 2>/dev/null; then
      awk '$1 ~ /^(RHSA|ALAS|CESA|ELSA|FEDORA|USN)-/ {print}' \
        "$tmp_raw" >"$tmp_security"
      security_status=available
    fi
    ;;
  apt)
    if ! apt list --upgradable >"$tmp_raw" 2>/dev/null; then
      printf 'apt failed to list available updates.\n' >&2
      exit 2
    fi
    awk 'NR > 1 && $1 ~ /\// {print}' "$tmp_raw" >"$tmp_updates"
    awk 'tolower($0) ~ /security/ {print}' "$tmp_updates" >"$tmp_security"
    security_status=available
    ;;
  zypper)
    if ! zypper --non-interactive list-updates >"$tmp_raw" 2>/dev/null; then
      printf 'zypper failed to list available updates.\n' >&2
      exit 2
    fi
    awk '/^[[:space:]]*v[[:space:]]*\|/ {print}' "$tmp_raw" >"$tmp_updates"
    ;;
esac

update_count=$(awk 'END {print NR + 0}' "$tmp_updates")
if [[ $security_status == available ]]; then
  security_count=$(awk 'END {print NR + 0}' "$tmp_security")
else
  security_count=unknown
fi

reboot_status=unknown
if [[ -e /var/run/reboot-required ]]; then
  reboot_status=required
elif command -v needs-restarting >/dev/null 2>&1; then
  needs-restarting -r >/dev/null 2>&1
  reboot_check=$?
  case "$reboot_check" in
    0) reboot_status=not-required ;;
    1) reboot_status=required ;;
  esac
fi

{
  printf 'Linux Package Update Report\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Running kernel: %s\n' "$(uname -r 2>/dev/null || printf unknown)"
  printf 'Package manager: %s\n' "$manager"
  printf 'Metadata refresh performed: no\n'
  printf 'Available updates: %s\n' "$update_count"
  printf 'Security advisories/updates: %s\n' "$security_count"
  printf 'Reboot status: %s\n' "$reboot_status"

  printf '\n== Available updates (maximum %s) ==\n' "$max_results"
  if (( update_count == 0 )); then
    printf 'None found in current metadata.\n'
  else
    head -n "$max_results" "$tmp_updates"
    if (( update_count > max_results )); then
      printf '[Additional updates omitted: %d]\n' "$((update_count - max_results))"
    fi
  fi

  printf '\n== Security updates/advisories (maximum %s) ==\n' "$max_results"
  if [[ $security_status != available ]]; then
    printf 'Unavailable from this package manager or installed plugins.\n'
  elif (( security_count == 0 )); then
    printf 'None identified in current metadata.\n'
  else
    head -n "$max_results" "$tmp_security"
    if (( security_count > max_results )); then
      printf '[Additional security entries omitted: %d]\n' "$((security_count - max_results))"
    fi
  fi

  printf '\n== Guidance ==\n'
  printf 'Review package dependencies and maintenance requirements before applying updates.\n'
  printf 'Refresh repository metadata according to policy before making a final patch decision.\n'
} >"$tmp_report"

if [[ -n $output ]]; then
  cp -- "$tmp_report" "$output"
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

(( update_count == 0 )) && exit 0
exit 1
