#!/usr/bin/env bash
# Create a read-only Linux host triage snapshot for SOC investigation.
#
# Usage:
#   ./host_triage_snapshot.sh
#   sudo ./host_triage_snapshot.sh -n 100 -o /secure/path/triage.txt
#
# Options:
#   -n COUNT   maximum login and journal entries per section (default: 50)
#   -o FILE    output file (default: ./host_triage_HOST_TIMESTAMP.txt)
#   -h         show help
#
# Run with elevated privileges only when authorized and when process names,
# socket owners, or journal entries are hidden from the current account.

set -uo pipefail
umask 077

max_entries=50
output_file=""

usage() {
  sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//'
}

while getopts ":n:o:h" option; do
  case "$option" in
    n) max_entries=$OPTARG ;;
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

if ! [[ $max_entries =~ ^[1-9][0-9]*$ ]]; then
  printf 'Error: -n must be a positive integer.\n' >&2
  exit 2
fi

if [[ -z $output_file ]]; then
  safe_host=$(hostname | tr -c '[:alnum:]._- ' '_' | tr -d ' ')
  output_file="./host_triage_${safe_host}_$(date +%Y%m%d_%H%M%S).txt"
fi

output_dir=$(dirname -- "$output_file")
if [[ ! -d $output_dir ]]; then
  printf 'Error: output directory does not exist: %s\n' "$output_dir" >&2
  exit 2
fi

if ! : >"$output_file"; then
  printf 'Error: cannot write to %s\n' "$output_file" >&2
  exit 1
fi
chmod 600 "$output_file"

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

{
  printf 'LINUX HOST TRIAGE SNAPSHOT\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Collector user: %s (UID %s)\n' "$(id -un)" "$(id -u)"
  printf 'Output: %s\n' "$output_file"

  run_command "HOST AND OPERATING SYSTEM" hostnamectl
  run_command "KERNEL" uname -a
  run_command "UPTIME AND LOAD" uptime
  run_command "FILESYSTEM USAGE" df -hP
  run_command "MEMORY USAGE" free -h
  run_command "CURRENT USERS" who -a
  run_command "RECENT LOGINS" last -n "$max_entries"

  run_command "NETWORK ADDRESSES" ip -brief address
  run_command "NETWORK ROUTES" ip route
  run_command "LISTENING SOCKETS" ss -lntup

  section "TOP PROCESSES BY CPU"
  if command -v ps >/dev/null 2>&1; then
    ps aux --sort=-%cpu 2>&1 | head -n "$((max_entries + 1))"
  else
    printf '[Unavailable: ps]\n'
  fi

  section "TOP PROCESSES BY MEMORY"
  if command -v ps >/dev/null 2>&1; then
    ps aux --sort=-%mem 2>&1 | head -n "$((max_entries + 1))"
  else
    printf '[Unavailable: ps]\n'
  fi

  run_command "FAILED SYSTEMD UNITS" systemctl --failed --no-pager
  run_command "RECENT WARNING-TO-ALERT JOURNAL EVENTS" \
    journalctl --priority warning..alert --since "1 hour ago" \
      --lines "$max_entries" --no-pager --output short-iso

  section "CURRENT USER CRONTAB"
  if command -v crontab >/dev/null 2>&1; then
    crontab -l 2>&1 || printf '[No readable crontab for current user]\n'
  else
    printf '[Unavailable: crontab]\n'
  fi
} >>"$output_file"

printf 'Triage snapshot written to %s\n' "$output_file"
