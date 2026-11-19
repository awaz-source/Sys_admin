#!/usr/bin/env bash
# Inventory loaded Linux kernel modules and highlight attributes needing review.
# Read-only: this script never loads, unloads, or changes a kernel module.
#
# Examples:
#   sudo ./kernel_module_inventory.sh
#   ./kernel_module_inventory.sh -s /sys/module -o kernel-modules.txt
#
# Exit codes: 0 no findings, 1 review findings present, 2 collection/input error.

set -uo pipefail
umask 077

module_root=/sys/module
output=""

usage() {
  cat <<'USAGE'
Usage: kernel_module_inventory.sh [-s SYS_MODULE_DIR] [-o REPORT]

Options:
  -s DIR     sysfs module directory (default: /sys/module)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

The report combines sysfs state with modinfo metadata when available. It flags
module taint indicators, unsigned loadable modules, and module files outside the
running kernel's /lib/modules tree. These are triage leads, not proof of malware;
custom drivers and systems without module-signing enforcement can be legitimate.
USAGE
}

while getopts ":s:o:h" option; do
  case "$option" in
    s) module_root=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! -d $module_root ]]; then
  printf 'Kernel module directory was not found: %s\n' "$module_root" >&2
  exit 2
fi

kernel_release=$(uname -r 2>/dev/null) || {
  printf 'Unable to determine the running kernel release.\n' >&2
  exit 2
}

tmp_inventory=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_inventory" "$tmp_findings" "$tmp_report"' EXIT

module_count=0
finding_count=0
modinfo_available=no
command -v modinfo >/dev/null 2>&1 && modinfo_available=yes

read_sysfs_value() {
  local path=$1 fallback=$2 value
  if [[ -r $path ]]; then
    IFS= read -r value <"$path" || true
    printf '%s' "${value:-$fallback}"
  else
    printf '%s' "$fallback"
  fi
}

safe_field() {
  local value=$1
  value=${value//$'\t'/ }
  value=${value//$'\n'/ }
  printf '%s' "${value:-unknown}"
}

while IFS= read -r -d '' module_dir; do
  module_count=$((module_count + 1))
  module_name=${module_dir##*/}
  taint=$(read_sysfs_value "$module_dir/taint" none)
  refcount=$(read_sysfs_value "$module_dir/refcnt" unknown)
  holder_count=0
  parameter_count=0
  [[ -d $module_dir/holders ]] && holder_count=$(find "$module_dir/holders" -mindepth 1 -maxdepth 1 -type l -printf . 2>/dev/null | wc -c)
  [[ -d $module_dir/parameters ]] && parameter_count=$(find "$module_dir/parameters" -mindepth 1 -maxdepth 1 -type f -printf . 2>/dev/null | wc -c)

  filename=builtin-or-unknown
  signer=unknown
  description=unknown
  if [[ $modinfo_available == yes ]]; then
    filename=$(modinfo -F filename -- "$module_name" 2>/dev/null | head -n 1)
    signer=$(modinfo -F signer -- "$module_name" 2>/dev/null | head -n 1)
    description=$(modinfo -F description -- "$module_name" 2>/dev/null | head -n 1)
    [[ -n $filename ]] || filename=builtin-or-unknown
    [[ -n $signer ]] || signer=unsigned
    [[ -n $description ]] || description=unknown
  fi

  severity=OK
  reasons=()
  if [[ $taint != none && $taint != 0 && $taint != '-' ]]; then
    severity=HIGH
    reasons+=("module taint=$taint")
  fi
  if [[ $filename != builtin-or-unknown && $filename != '(builtin)' ]]; then
    if [[ $signer == unsigned ]]; then
      [[ $severity == HIGH ]] || severity=MEDIUM
      reasons+=('no module signer reported')
    fi
    if [[ $filename != "/lib/modules/$kernel_release/"* ]]; then
      severity=HIGH
      reasons+=('file outside running kernel module tree')
    fi
  fi

  safe_name=$(safe_field "$module_name")
  safe_file=$(safe_field "$filename")
  safe_signer=$(safe_field "$signer")
  safe_description=$(safe_field "$description")
  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n' \
    "$severity" "$safe_name" "$refcount" "$holder_count" "$parameter_count" \
    "$taint" "$safe_signer" "$safe_file" "$safe_description" >>"$tmp_inventory"

  if [[ $severity != OK ]]; then
    reason_text=$(IFS=', '; printf '%s' "${reasons[*]}")
    printf '%s\t%s\t%s\n' "$severity" "$safe_name" "$reason_text" >>"$tmp_findings"
    finding_count=$((finding_count + 1))
  fi
done < <(find "$module_root" -mindepth 1 -maxdepth 1 -type d -print0 2>/dev/null | sort -z)

if (( module_count == 0 )); then
  printf 'No module directories were found under: %s\n' "$module_root" >&2
  exit 2
fi

{
  printf 'Loaded Kernel Module Inventory\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Kernel release: %s\n' "$kernel_release"
  printf 'Module source: %s\n' "$module_root"
  printf 'modinfo available: %s\n' "$modinfo_available"
  printf 'Modules inventoried: %d\n' "$module_count"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Module inventory ==\n'
  printf 'STATUS | MODULE | REFCNT | HOLDERS | PARAMETERS | TAINT | SIGNER | FILE | DESCRIPTION\n'
  sort -t $'\t' -k1,1 -k2,2 "$tmp_inventory" | tr '\t' '|'

  printf '\n== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No tainted, unsigned, or unexpectedly located loadable modules were identified.\n'
  else
    printf 'SEVERITY | MODULE | REASONS\n'
    sort -t $'\t' -k1,1 -k2,2 "$tmp_findings" | tr '\t' '|'
  fi

  printf '\n== Investigation guidance ==\n'
  printf 'Compare findings with approved drivers, package ownership, Secure Boot policy, and host baselines.\n'
  printf 'Preserve module files and hashes before containment; do not unload drivers without impact review.\n'
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
