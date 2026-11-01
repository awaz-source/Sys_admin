#!/usr/bin/env bash
# Read-only Docker/Podman inventory for SOC triage and exposure review.
#
# Examples:
#   sudo ./container_runtime_inventory.sh
#   ./container_runtime_inventory.sh -r podman
#   ./container_runtime_inventory.sh -r docker -o container-report.txt
#
# Exit codes: 0 inventory completed without risky settings, 1 review findings
# detected, 2 runtime/argument error.

set -uo pipefail
umask 077

runtime=auto
output=""

usage() {
  cat <<'USAGE'
Usage: container_runtime_inventory.sh [-r auto|docker|podman] [-o REPORT]

Options:
  -r RUNTIME  Container runtime to inspect (default: auto)
  -o REPORT   Save the report with permissions set to 600
  -h          Show this help

The script is read-only and does not collect container environment variables.
Run with sufficient permission to query the selected container runtime.
Findings are review indicators and should be evaluated against workload needs.
USAGE
}

while getopts ":r:o:h" option; do
  case "$option" in
    r) runtime=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

case "$runtime" in
  auto)
    if command -v docker >/dev/null 2>&1; then
      runtime=docker
    elif command -v podman >/dev/null 2>&1; then
      runtime=podman
    else
      printf 'Neither docker nor podman was found.\n' >&2
      exit 2
    fi
    ;;
  docker|podman)
    if ! command -v "$runtime" >/dev/null 2>&1; then
      printf 'Requested runtime was not found: %s\n' "$runtime" >&2
      exit 2
    fi
    ;;
  *)
    printf 'Runtime must be auto, docker, or podman.\n' >&2
    exit 2
    ;;
esac

if ! runtime_version=$($runtime version --format '{{.Server.Version}}' 2>/dev/null); then
  printf 'Unable to query %s. Check that the runtime is running and accessible.\n' "$runtime" >&2
  exit 2
fi

tmp_report=$(mktemp)
trap 'rm -f "$tmp_report"' EXIT

mapfile -t container_ids < <($runtime ps -aq 2>/dev/null)
if ! $runtime ps -a --format '{{.ID}}\t{{.Names}}\t{{.Image}}\t{{.Status}}\t{{.Ports}}' \
  >"$tmp_report.list" 2>/dev/null; then
  printf 'Unable to list %s containers.\n' "$runtime" >&2
  exit 2
fi
trap 'rm -f "$tmp_report" "$tmp_report.list"' EXIT

{
  printf 'Container Runtime Inventory\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Runtime: %s %s\n' "$runtime" "$runtime_version"
  printf 'Containers: %d\n' "${#container_ids[@]}"
  printf '\n== Container summary ==\n'
  if (( ${#container_ids[@]} == 0 )); then
    printf 'No containers found.\n'
  else
    printf 'ID\tNAME\tIMAGE\tSTATUS\tPORTS\n'
    cat "$tmp_report.list"
  fi
} >"$tmp_report"

findings=0
inspect_failures=0
inspect_format='{{.Id}}|{{.Name}}|{{.Config.Image}}|{{.HostConfig.Privileged}}|{{.HostConfig.NetworkMode}}|{{.HostConfig.PidMode}}|{{.HostConfig.ReadonlyRootfs}}|{{json .HostConfig.CapAdd}}|{{json .Mounts}}'

printf '\n== Isolation and mount review ==\n' >>"$tmp_report"
for id in "${container_ids[@]}"; do
  if ! details=$($runtime inspect --format "$inspect_format" "$id" 2>/dev/null); then
    printf '[ERROR] id=%s could not be inspected\n' "$id" >>"$tmp_report"
    inspect_failures=$((inspect_failures + 1))
    findings=$((findings + 1))
    continue
  fi

  IFS='|' read -r full_id name image privileged network_mode pid_mode readonly_root cap_add mounts <<<"$details"
  name=${name#/}
  short_id=${full_id:0:12}
  printf 'container=%s id=%s image=%s privileged=%s network=%s pid=%s readonly_root=%s capabilities=%s\n' \
    "$name" "$short_id" "$image" "$privileged" "$network_mode" \
    "${pid_mode:-private}" "$readonly_root" "$cap_add" >>"$tmp_report"

  if [[ $privileged == true ]]; then
    printf '  [HIGH] Privileged container bypasses normal isolation controls.\n' >>"$tmp_report"
    findings=$((findings + 1))
  fi
  if [[ $network_mode == host ]]; then
    printf '  [HIGH] Container shares the host network namespace.\n' >>"$tmp_report"
    findings=$((findings + 1))
  fi
  if [[ $pid_mode == host ]]; then
    printf '  [HIGH] Container shares the host PID namespace.\n' >>"$tmp_report"
    findings=$((findings + 1))
  fi
  if [[ ${cap_add^^} == *SYS_ADMIN* || ${cap_add^^} == *SYS_PTRACE* ]]; then
    printf '  [HIGH] Powerful capability added: %s\n' "$cap_add" >>"$tmp_report"
    findings=$((findings + 1))
  fi
  if [[ $mounts == *docker.sock* || $mounts == *podman.sock* ]]; then
    printf '  [CRITICAL] Container runtime socket is mounted.\n' >>"$tmp_report"
    findings=$((findings + 1))
  fi
  if [[ $mounts == *'"Destination":"/etc"'* ||
        $mounts == *'"Destination":"/proc"'* ||
        $mounts == *'"Destination":"/sys"'* ]]; then
    printf '  [HIGH] Sensitive host-style destination is mounted.\n' >>"$tmp_report"
    findings=$((findings + 1))
  fi
done

{
  printf '\n== Summary ==\n'
  printf 'Review findings: %d\n' "$findings"
  printf 'Inspection failures: %d\n' "$inspect_failures"
  if (( findings == 0 )); then
    printf 'No high-risk isolation settings were detected.\n'
  else
    printf 'Review flagged settings against approved workload requirements and runtime audit logs.\n'
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
