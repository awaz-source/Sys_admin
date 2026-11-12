#!/usr/bin/env bash
# Produce a read-only systemd service state and dependency impact report.
#
# Examples:
#   ./systemd_service_impact_report.sh sshd nginx
#   ./systemd_service_impact_report.sh -i services.txt -r 5
#   ./systemd_service_impact_report.sh -i services.txt -o service-impact.txt
#
# Input files contain one service per line; blank lines and # comments are ignored.
# Exit codes: 0 no review findings, 1 findings present, 2 input/collection error.

set -uo pipefail
umask 077

input=""
output=""
restart_threshold=5

usage() {
  cat <<'USAGE'
Usage: systemd_service_impact_report.sh [-i FILE] [-r COUNT] [-o REPORT] [SERVICE ...]

Options:
  -i FILE    Read one service name per line; comments start with #
  -r COUNT   Restart count that triggers review (default: 5)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

Services from FILE and command-line arguments are combined and de-duplicated.
Names without a unit suffix receive .service. The script calls systemctl show
only; it does not start, stop, enable, disable, or restart units.
USAGE
}

while getopts ":i:r:o:h" option; do
  case "$option" in
    i) input=$OPTARG ;;
    r) restart_threshold=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done
shift $((OPTIND - 1))

if [[ ! $restart_threshold =~ ^[1-9][0-9]*$ ]]; then
  printf 'COUNT must be a positive integer.\n' >&2
  exit 2
fi
if [[ -n $input && ! -r $input ]]; then
  printf 'Input file is not readable: %s\n' "$input" >&2
  exit 2
fi
command -v systemctl >/dev/null 2>&1 || {
  printf 'systemctl was not found.\n' >&2
  exit 2
}

tmp_names=$(mktemp)
tmp_units=$(mktemp)
tmp_details=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_names" "$tmp_units" "$tmp_details" "$tmp_findings" "$tmp_report"' EXIT

if [[ -n $input ]]; then
  while IFS= read -r line || [[ -n $line ]]; do
    line=${line%%#*}
    line=${line#"${line%%[![:space:]]*}"}
    line=${line%"${line##*[![:space:]]}"}
    [[ -n $line ]] && printf '%s\n' "$line" >>"$tmp_names"
  done <"$input"
fi
for service in "$@"; do
  printf '%s\n' "$service" >>"$tmp_names"
done

if [[ ! -s $tmp_names ]]; then
  printf 'Provide at least one SERVICE or a non-empty -i FILE.\n' >&2
  exit 2
fi

while IFS= read -r service; do
  if [[ ! $service =~ ^[[:alnum:]_@.:-]+$ ]]; then
    printf 'Invalid service name: %s\n' "$service" >&2
    exit 2
  fi
  [[ $service == *.* ]] || service="${service}.service"
  printf '%s\n' "$service" >>"$tmp_units"
done <"$tmp_names"
sort -u -o "$tmp_units" "$tmp_units"

finding_count=0
add_finding() {
  local severity=$1 unit=$2 reason=$3
  printf '%s\t%s\t%s\n' "$severity" "$unit" "$reason" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
}

unit_count=0
while IFS= read -r unit; do
  unit_count=$((unit_count + 1))
  show_output=$(systemctl show --no-pager \
    --property=Id,Description,LoadState,ActiveState,SubState,UnitFileState,FragmentPath,NRestarts,ExecMainStatus,Requires,Wants,RequiredBy,WantedBy,After,Before \
    -- "$unit" 2>/dev/null) || {
      printf 'Unable to inspect systemd unit: %s\n' "$unit" >&2
      exit 2
    }

  declare -A property=()
  while IFS='=' read -r key value; do
    [[ -n $key ]] && property["$key"]=$value
  done <<<"$show_output"

  load_state=${property[LoadState]:-unknown}
  active_state=${property[ActiveState]:-unknown}
  sub_state=${property[SubState]:-unknown}
  unit_file_state=${property[UnitFileState]:-unknown}
  restarts=${property[NRestarts]:-0}
  exec_status=${property[ExecMainStatus]:-unknown}
  description=${property[Description]:-}
  fragment=${property[FragmentPath]:-}
  requires=${property[Requires]:-}
  wants=${property[Wants]:-}
  required_by=${property[RequiredBy]:-}
  wanted_by=${property[WantedBy]:-}
  after=${property[After]:-}
  before=${property[Before]:-}

  [[ $restarts =~ ^[0-9]+$ ]] || restarts=0

  {
    printf 'Unit: %s\n' "$unit"
    printf '  Description: %s\n' "${description:-none}"
    printf '  Load/active/sub: %s / %s / %s\n' "$load_state" "$active_state" "$sub_state"
    printf '  Unit file state: %s\n' "$unit_file_state"
    printf '  Unit file: %s\n' "${fragment:-none}"
    printf '  Restart count: %s\n' "$restarts"
    printf '  Last main exit status: %s\n' "$exec_status"
    printf '  Requires: %s\n' "${requires:-none}"
    printf '  Wants: %s\n' "${wants:-none}"
    printf '  Required by: %s\n' "${required_by:-none}"
    printf '  Wanted by: %s\n' "${wanted_by:-none}"
    printf '  Starts after: %s\n' "${after:-none}"
    printf '  Starts before: %s\n\n' "${before:-none}"
  } >>"$tmp_details"

  if [[ $load_state == not-found ]]; then
    add_finding HIGH "$unit" 'unit was not found'
  elif [[ $active_state == failed ]]; then
    add_finding HIGH "$unit" "unit is failed (main exit status $exec_status)"
  fi
  if (( restarts >= restart_threshold )); then
    add_finding MEDIUM "$unit" "$restarts recorded restarts (threshold $restart_threshold)"
  fi
done <"$tmp_units"

{
  printf 'Systemd Service Impact Report\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Units inspected: %d\n' "$unit_count"
  printf 'Restart review threshold: %d\n' "$restart_threshold"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Unit details ==\n'
  cat "$tmp_details"

  printf '== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No failed, missing, or restart-threshold conditions were identified.\n'
  else
    sort -t $'\t' -k1,1 -k2,2 "$tmp_findings" \
      | awk -F'\t' '{print $1 " | " $2 " | " $3}'
  fi

  printf '\n== Change-planning guidance ==\n'
  printf 'Review Requires/Wants before stopping a unit and Required-by/Wanted-by before changing it.\n'
  printf 'Confirm maintenance windows, health checks, rollback steps, and service ownership.\n'
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

(( finding_count == 0 )) && exit 0
exit 1
