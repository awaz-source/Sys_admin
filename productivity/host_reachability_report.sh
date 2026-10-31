#!/usr/bin/env bash
# Check DNS resolution and TCP service reachability for a list of hosts.
#
# Inventory format (one target per line):
#   server1.example.com
#   db1.example.com 5432
#   192.0.2.25 443
# Lines beginning with # and blank lines are ignored.
#
# Examples:
#   ./host_reachability_report.sh -f hosts.txt
#   ./host_reachability_report.sh -f hosts.txt -p 22 -t 3 -o report.csv
#
# Exit codes: 0 all targets reachable, 1 one or more checks failed,
# 2 invalid arguments or dependencies.

set -uo pipefail
umask 077

inventory=""
default_port=22
connect_timeout=3
output=""

usage() {
  cat <<'USAGE'
Usage: host_reachability_report.sh -f INVENTORY [-p PORT] [-t SECONDS] [-o CSV]

Options:
  -f INVENTORY  File containing "host" or "host port" entries
  -p PORT       Default TCP port when an entry omits one (default: 22)
  -t SECONDS    Per-target connection timeout (default: 3)
  -o CSV        Save CSV report with permissions set to 600
  -h            Show this help

This script performs DNS and TCP connection checks only. Use it solely against
systems you own or are authorized to administer.
USAGE
}

while getopts ":f:p:t:o:h" option; do
  case "$option" in
    f) inventory=$OPTARG ;;
    p) default_port=$OPTARG ;;
    t) connect_timeout=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z $inventory || ! -r $inventory ]]; then
  printf 'A readable inventory file is required.\n' >&2
  exit 2
fi
if [[ ! $default_port =~ ^[0-9]+$ ]] || (( default_port < 1 || default_port > 65535 )); then
  printf 'Default port must be between 1 and 65535.\n' >&2
  exit 2
fi
if [[ ! $connect_timeout =~ ^[1-9][0-9]*$ ]]; then
  printf 'Timeout must be a positive integer.\n' >&2
  exit 2
fi
for dependency in getent timeout awk; do
  if ! command -v "$dependency" >/dev/null 2>&1; then
    printf 'Required command not found: %s\n' "$dependency" >&2
    exit 2
  fi
done

tmp_report=$(mktemp)
trap 'rm -f "$tmp_report"' EXIT
printf 'host,port,resolved_address,dns_status,tcp_status\n' >"$tmp_report"

targets=0
failures=0
invalid_entries=0

while IFS= read -r raw_line || [[ -n $raw_line ]]; do
  line=${raw_line%%#*}
  read -r host port extra <<<"$line"
  [[ -n ${host:-} ]] || continue
  port=${port:-$default_port}
  targets=$((targets + 1))

  if [[ -n ${extra:-} || ! $host =~ ^[A-Za-z0-9._:-]+$ || ! $port =~ ^[0-9]+$ ]] ||
     (( port < 1 || port > 65535 )); then
    printf '"%s","%s",,"invalid","not-tested"\n' "$host" "$port" >>"$tmp_report"
    failures=$((failures + 1))
    invalid_entries=$((invalid_entries + 1))
    continue
  fi

  mapfile -t resolved_addresses < <(
    getent ahosts "$host" 2>/dev/null | awk '!seen[$1]++ {print $1}'
  )
  if (( ${#resolved_addresses[@]} == 0 )); then
    printf '"%s",%s,,"failed","not-tested"\n' "$host" "$port" >>"$tmp_report"
    failures=$((failures + 1))
    continue
  fi

  resolved=${resolved_addresses[0]}
  tcp_status=unreachable
  for address in "${resolved_addresses[@]}"; do
    if timeout "$connect_timeout" bash -c \
      'exec 3<>"/dev/tcp/$1/$2"' _ "$address" "$port" 2>/dev/null; then
      resolved=$address
      tcp_status=reachable
      break
    fi
  done
  if [[ $tcp_status == unreachable ]]; then
    failures=$((failures + 1))
  fi

  printf '"%s",%s,"%s","resolved","%s"\n' \
    "$host" "$port" "$resolved" "$tcp_status" >>"$tmp_report"
done <"$inventory"

if (( targets == 0 )); then
  printf 'Inventory contains no targets.\n' >&2
  exit 2
fi

if [[ -n $output ]]; then
  cp -- "$tmp_report" "$output"
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

printf 'Checked %d target(s): %d passed, %d failed (%d invalid).\n' \
  "$targets" "$((targets - failures))" "$failures" "$invalid_entries" >&2

(( failures == 0 )) && exit 0
exit 1
