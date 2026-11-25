#!/usr/bin/env bash
# Inventory listening TCP/UDP sockets and classify their network exposure.
#
# Usage:
#   network_listener_inventory.sh [-p] [-o REPORT]
#
# Options:
#   -p          Ask ss to include process details (may require elevated privileges).
#   -o REPORT   Save the report with mode 600 instead of printing it.
#   -h          Show this help.
#
# Exposure classes:
#   LOOPBACK  Bound only to localhost.
#   WILDCARD  Bound to all interfaces (review firewall policy).
#   SPECIFIC  Bound to a specific non-loopback address.
#
# This script is read-only. It requires Linux iproute2's ss command.
# Exit codes: 0 success; 2 invalid input or collection failure.

set -uo pipefail
umask 077

usage() {
  sed -n '2,17s/^# \{0,1\}//p' "$0"
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

include_processes=0
output=''
while getopts ':po:h' option; do
  case "$option" in
    p) include_processes=1 ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "-$OPTARG requires an argument" ;;
    \?) die "unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))
(( $# == 0 )) || die 'unexpected positional arguments'

command -v ss >/dev/null 2>&1 || die "required command not found: ss"
for command in awk cat chmod cp date dirname mktemp rm sort; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

work_dir=$(mktemp -d) || die 'could not create temporary directory'
trap 'rm -rf -- "$work_dir"' EXIT
raw_file=$work_dir/sockets
rows_file=$work_dir/rows
report_file=$work_dir/report

ss_args=(-H -lntu)
(( include_processes == 1 )) && ss_args+=(-p)
if ! ss "${ss_args[@]}" >"$raw_file"; then
  die 'ss could not collect listening sockets'
fi

# ss fields are: protocol, state, recv-q, send-q, local endpoint, peer endpoint.
# Everything after the peer endpoint is retained as optional process information.
if ! awk '
  function endpoint_address(endpoint, value) {
    value = endpoint
    sub(/:[^:]*$/, "", value)
    gsub(/^\[/, "", value)
    gsub(/\]$/, "", value)
    return value
  }
  function endpoint_port(endpoint, value) {
    value = endpoint
    sub(/^.*:/, "", value)
    return value
  }
  function exposure(address) {
    if (address == "127.0.0.1" || address == "::1") return "LOOPBACK"
    if (address == "0.0.0.0" || address == "::" || address == "*") return "WILDCARD"
    return "SPECIFIC"
  }
  NF >= 5 {
    address = endpoint_address($5)
    port = endpoint_port($5)
    process = "-"
    if (NF > 6) {
      process = $7
      for (i = 8; i <= NF; i++) process = process " " $i
      gsub(/\t/, " ", process)
    }
    printf "%s\t%s\t%s\t%s\t%s\n", exposure(address), $1, address, port, process
  }
' "$raw_file" | sort -t $'\t' -k1,1 -k2,2 -k4,4n >"$rows_file"; then
  die 'could not parse listening sockets'
fi

total=$(awk 'END { print NR + 0 }' "$rows_file")
loopback=$(awk -F '\t' '$1 == "LOOPBACK" { count++ } END { print count + 0 }' "$rows_file")
wildcard=$(awk -F '\t' '$1 == "WILDCARD" { count++ } END { print count + 0 }' "$rows_file")
specific=$(awk -F '\t' '$1 == "SPECIFIC" { count++ } END { print count + 0 }' "$rows_file")

{
  printf 'Network listener inventory\n'
  printf 'Generated: %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n\n' "$(hostname 2>/dev/null || printf unknown)"
  printf '%-10s %-7s %-39s %-8s %s\n' 'EXPOSURE' 'PROTO' 'LOCAL_ADDRESS' 'PORT' 'PROCESS'
  printf '%-10s %-7s %-39s %-8s %s\n' '----------' '-------' '---------------------------------------' '--------' '-------'
  while IFS=$'\t' read -r exposure proto address port process; do
    printf '%-10s %-7s %-39s %-8s %s\n' "$exposure" "$proto" "$address" "$port" "$process"
  done <"$rows_file"
  printf '\nSummary: %d total; %d loopback; %d wildcard; %d specific\n' \
    "$total" "$loopback" "$wildcard" "$specific"
  if (( wildcard > 0 )); then
    printf 'Review: wildcard listeners rely on host/network firewall policy for exposure control.\n'
  fi
} >"$report_file"

if [[ -n $output ]]; then
  output_dir=$(dirname -- "$output")
  [[ -d $output_dir ]] || die "output directory does not exist: $output_dir"
  cp -- "$report_file" "$output" || die "could not write report: $output"
  chmod 600 -- "$output" || die "could not secure report permissions: $output"
else
  cat "$report_file"
fi
