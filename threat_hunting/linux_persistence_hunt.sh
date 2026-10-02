#!/usr/bin/env bash
# Collect read-only Linux persistence indicators for threat hunting.
#
# Usage:
#   ./linux_persistence_hunt.sh
#   sudo ./linux_persistence_hunt.sh -d 14 -n 100 -o persistence-report.txt
#
# Options:
#   -d DAYS    recent-change window in days (default: 7)
#   -n COUNT   maximum results per file section (default: 50)
#   -o FILE    save the report to FILE instead of standard output
#   -h         show help
#
# Findings require analyst review. Legitimate software commonly uses systemd,
# cron, shell profiles, and SSH keys for normal administration.

set -uo pipefail
umask 077

days=7
max_results=50
output_file=""

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts ":d:n:o:h" option; do
  case "$option" in
    d) days=$OPTARG ;;
    n) max_results=$OPTARG ;;
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

if ! [[ $days =~ ^[1-9][0-9]*$ ]]; then
  printf 'Error: -d must be a positive integer.\n' >&2
  exit 2
fi

if ! [[ $max_results =~ ^[1-9][0-9]*$ ]]; then
  printf 'Error: -n must be a positive integer.\n' >&2
  exit 2
fi

report_file=$(mktemp)
trap 'rm -f "$report_file"' EXIT

section() {
  printf '\n===== %s =====\n' "$1"
}

run_command() {
  local title=$1
  shift
  section "$title"

  if command -v "$1" >/dev/null 2>&1; then
    "$@" 2>&1 || printf '[Command exited with status %s]\n' "$?"
  else
    printf '[Unavailable: %s]\n' "$1"
  fi
}

print_limited_findings() {
  local title=$1
  shift
  section "$title"

  if (( $# == 0 )); then
    printf '[No applicable paths found]\n'
    return
  fi

  find "$@" -xdev -type f -mtime "-$days" \
    -printf '%TY-%Tm-%Td %TH:%TM:%TS  %M  %u:%g  %p\n' 2>/dev/null |
    sort -r |
    head -n "$max_results" || true
}

{
  printf 'LINUX PERSISTENCE HUNT REPORT\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Host: %s\n' "$(hostname)"
  printf 'Collector: %s (UID %s)\n' "$(id -un)" "$(id -u)"
  printf 'Recent-change window: %s days\n' "$days"

  run_command "ENABLED SYSTEMD SERVICES" \
    systemctl list-unit-files --type=service --state=enabled --no-pager
  run_command "SYSTEMD TIMERS" systemctl list-timers --all --no-pager

  section "SYSTEMD UNIT FILES AND OVERRIDES"
  if [[ -d /etc/systemd/system ]]; then
    find /etc/systemd/system -xdev \( -type f -o -type l \) \
      -printf '%y  %M  %u:%g  %TY-%Tm-%Td %TH:%TM:%TS  %p -> %l\n' \
      2>/dev/null | sort
  else
    printf '[/etc/systemd/system not present]\n'
  fi

  section "SYSTEM CRON FILES"
  cron_paths=()
  for path in /etc/crontab /etc/cron.d /etc/cron.daily /etc/cron.hourly \
    /etc/cron.weekly /etc/cron.monthly; do
    [[ -e $path ]] && cron_paths+=("$path")
  done
  if (( ${#cron_paths[@]} > 0 )); then
    find "${cron_paths[@]}" -xdev -type f \
      -printf '%M  %u:%g  %TY-%Tm-%Td %TH:%TM:%TS  %p\n' 2>/dev/null |
      sort
  else
    printf '[No standard system cron paths found]\n'
  fi

  section "CURRENT USER CRONTAB"
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>&1 || printf '[No readable crontab for current user]\n'
  else
    printf '[Unavailable: crontab]\n'
  fi

  section "AUTHORIZED SSH KEY FILES"
  ssh_roots=()
  [[ -d /root ]] && ssh_roots+=(/root)
  [[ -d /home ]] && ssh_roots+=(/home)
  if (( ${#ssh_roots[@]} > 0 )); then
    while IFS= read -r key_file; do
      stat -c '%A  %U:%G  %y  %n' "$key_file" 2>/dev/null || true
      if command -v ssh-keygen >/dev/null 2>&1; then
        ssh-keygen -lf "$key_file" 2>/dev/null || \
          printf '[Could not read fingerprints from %s]\n' "$key_file"
      fi
    done < <(
      find "${ssh_roots[@]}" -xdev -type f -path '*/.ssh/authorized_keys*' \
        2>/dev/null | sort
    )
  fi

  profile_paths=()
  for path in /etc/profile /etc/profile.d /root /home; do
    [[ -e $path ]] && profile_paths+=("$path")
  done
  print_limited_findings "RECENT FILES IN PROFILE LOCATIONS" \
    "${profile_paths[@]}"

  persistence_paths=()
  for path in /etc/systemd/system /etc/cron.d /etc/cron.daily \
    /usr/local/bin /usr/local/sbin; do
    [[ -e $path ]] && persistence_paths+=("$path")
  done
  print_limited_findings "RECENT FILES IN PERSISTENCE LOCATIONS" \
    "${persistence_paths[@]}"

  section "RECENT EXECUTABLES IN TEMPORARY LOCATIONS"
  temp_paths=()
  for path in /tmp /var/tmp /dev/shm; do
    [[ -d $path ]] && temp_paths+=("$path")
  done
  if (( ${#temp_paths[@]} > 0 )); then
    find "${temp_paths[@]}" -xdev -type f -perm /111 -mtime "-$days" \
      -printf '%TY-%Tm-%Td %TH:%TM:%TS  %M  %u:%g  %s bytes  %p\n' \
      2>/dev/null | sort -r | head -n "$max_results" || true
  else
    printf '[No temporary paths found]\n'
  fi

  printf '\nAnalyst note: compare findings with approved baselines and change records.\n'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 "$report_file" "$output_file"
  printf 'Report written to %s\n' "$output_file"
else
  cat "$report_file"
fi
