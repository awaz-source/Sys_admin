#!/usr/bin/env bash
# Read-only hunt for unexpected Linux TCP/UDP listeners.
#
# Examples:
#   sudo ./network_listener_hunt.sh
#   sudo ./network_listener_hunt.sh -a 22,53,80,443,8443 -o listeners.txt
#   ss -H -lntup > socket-snapshot.txt
#   ./network_listener_hunt.sh -f socket-snapshot.txt -a 22,443
#
# Exit codes: 0 no review findings, 1 findings detected, 2 input error.

set -uo pipefail
umask 077

approved_ports="22,53,67,68,80,123,443"
snapshot_file=""
output=""

usage() {
  cat <<'USAGE'
Usage: network_listener_hunt.sh [-a PORTS] [-f SS_SNAPSHOT] [-o REPORT]

Options:
  -a PORTS        Comma-separated approved wildcard-listener ports
                  (default: 22,53,67,68,80,123,443)
  -f SS_SNAPSHOT  Analyze saved output from "ss -H -lntup"
  -o REPORT       Save the report with permissions set to 600
  -h              Show this help

Without -f, the script runs "ss -H -lntup" locally. Run with sudo for process
details. Findings are hunting leads: validate them against the host role,
firewall policy, deployment records, and network telemetry.
USAGE
}

while getopts ":a:f:o:h" option; do
  case "$option" in
    a) approved_ports=$OPTARG ;;
    f) snapshot_file=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! $approved_ports =~ ^[0-9]+(,[0-9]+)*$ ]]; then
  printf 'Approved ports must be a comma-separated numeric list.\n' >&2
  exit 2
fi
IFS=',' read -ra port_values <<<"$approved_ports"
for port_value in "${port_values[@]}"; do
  if (( port_value < 1 || port_value > 65535 )); then
    printf 'Approved port is outside 1-65535: %s\n' "$port_value" >&2
    exit 2
  fi
done
approved_lookup=",$approved_ports,"

tmp_snapshot=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_snapshot" "$tmp_report"' EXIT

if [[ -n $snapshot_file ]]; then
  if [[ ! -r $snapshot_file ]]; then
    printf 'Socket snapshot is not readable: %s\n' "$snapshot_file" >&2
    exit 2
  fi
  cp -- "$snapshot_file" "$tmp_snapshot"
  source_description=$snapshot_file
else
  if ! command -v ss >/dev/null 2>&1; then
    printf 'The ss command is required when -f is not supplied.\n' >&2
    exit 2
  fi
  if ! ss -H -lntup >"$tmp_snapshot" 2>/dev/null; then
    printf 'Unable to collect listening sockets with ss.\n' >&2
    exit 2
  fi
  source_description="live host"
fi

listeners=0
findings=0
unparsed=0

{
  printf 'Linux Network Listener Hunt\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Source: %s\n' "$source_description"
  printf 'Approved wildcard ports: %s\n' "$approved_ports"
  printf '\n== Listener review ==\n'
} >"$tmp_report"

while IFS= read -r line || [[ -n $line ]]; do
  [[ -n $line ]] || continue
  read -r protocol state _ _ local_endpoint peer_endpoint remainder <<<"$line"

  if [[ $protocol != tcp && $protocol != udp ]] ||
     [[ -z ${local_endpoint:-} || $local_endpoint != *:* ]]; then
    printf '[UNPARSED] %s\n' "$line" >>"$tmp_report"
    unparsed=$((unparsed + 1))
    continue
  fi

  port=${local_endpoint##*:}
  address=${local_endpoint%:*}
  if [[ ! $port =~ ^[0-9]+$ ]] || (( port < 1 || port > 65535 )); then
    printf '[UNPARSED] %s\n' "$line" >>"$tmp_report"
    unparsed=$((unparsed + 1))
    continue
  fi

  listeners=$((listeners + 1))
  process=$(printf '%s\n' "$line" | sed -n 's/.*users:(("\([^"]*\)".*/\1/p')
  process=${process:-unknown}
  printf 'protocol=%s state=%s local=%s peer=%s process=%s\n' \
    "$protocol" "$state" "$local_endpoint" "${peer_endpoint:-unknown}" "$process" \
    >>"$tmp_report"

  wildcard=false
  case "$address" in
    0.0.0.0|'::'|'[::]'|'*') wildcard=true ;;
  esac

  if [[ $wildcard == true && $approved_lookup != *",$port,"* ]]; then
    printf '  [HIGH] Unapproved port listens on every interface.\n' >>"$tmp_report"
    findings=$((findings + 1))
  fi

  case "${process,,}" in
    nc|ncat|netcat|socat)
      printf '  [HIGH] Dual-use relay or netcat-style listener requires validation.\n' >>"$tmp_report"
      findings=$((findings + 1))
      ;;
  esac
done <"$tmp_snapshot"

{
  printf '\n== Summary ==\n'
  printf 'Listeners inspected: %d\n' "$listeners"
  printf 'Unparsed lines: %d\n' "$unparsed"
  printf 'Findings requiring review: %d\n' "$findings"
  if (( findings == 0 )); then
    printf 'No listeners matched the configured hunting conditions.\n'
  else
    printf 'Confirm each finding against the approved service inventory and firewall exposure.\n'
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
