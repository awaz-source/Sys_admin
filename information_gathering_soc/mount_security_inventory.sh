#!/usr/bin/env bash
# Inventory Linux mounts and flag risky execution/device/SUID option combinations.
# Read-only: this script does not mount, unmount, or remount filesystems.
#
# Examples:
#   ./mount_security_inventory.sh
#   ./mount_security_inventory.sh -i saved-findmnt.txt
#   ./mount_security_inventory.sh -o mount-inventory.txt
#
# Input format: TARGET SOURCE FSTYPE OPTIONS, as produced by:
#   findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS
#
# Exit codes: 0 no findings, 1 review findings present, 2 input/collection error.

set -uo pipefail
umask 077

input=""
output=""

usage() {
  cat <<'USAGE'
Usage: mount_security_inventory.sh [-i FINDMNT_FILE] [-o REPORT]

Options:
  -i FILE    Analyze saved findmnt output instead of the live host
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

The expected input columns are TARGET SOURCE FSTYPE OPTIONS. The script checks
temporary and remote filesystems for missing noexec, nosuid, and nodev options,
and highlights writable /boot mounts. Findings are review leads; application
requirements may justify particular mount options.
USAGE
}

while getopts ":i:o:h" option; do
  case "$option" in
    i) input=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -n $input && ! -r $input ]]; then
  printf 'Input file is not readable: %s\n' "$input" >&2
  exit 2
fi

tmp_raw=$(mktemp)
tmp_inventory=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_raw" "$tmp_inventory" "$tmp_findings" "$tmp_report"' EXIT

source_description=""
if [[ -n $input ]]; then
  source_description=$input
  cp -- "$input" "$tmp_raw" || exit 2
else
  command -v findmnt >/dev/null 2>&1 || {
    printf 'findmnt was not found; provide saved output with -i FILE.\n' >&2
    exit 2
  }
  source_description='live findmnt inventory'
  findmnt -rn -o TARGET,SOURCE,FSTYPE,OPTIONS >"$tmp_raw" 2>/dev/null || {
    printf 'Unable to collect mount information with findmnt.\n' >&2
    exit 2
  }
fi

mount_count=0
remote_count=0
finding_count=0

add_finding() {
  local severity=$1 target=$2 reason=$3
  printf '%s\t%s\t%s\n' "$severity" "$target" "$reason" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
}

has_option() {
  local options=$1 expected=$2
  [[ ",$options," == *",$expected,"* ]]
}

while read -r target source filesystem options extra; do
  [[ -n ${target:-} ]] || continue
  [[ ${target:0:1} != '#' ]] || continue
  if [[ -n ${extra:-} || -z ${source:-} || -z ${filesystem:-} || -z ${options:-} ]]; then
    printf 'Malformed findmnt input line: %s %s %s %s %s\n' \
      "${target:-}" "${source:-}" "${filesystem:-}" "${options:-}" "${extra:-}" >&2
    exit 2
  fi

  mount_count=$((mount_count + 1))
  printf '%s\t%s\t%s\t%s\n' "$target" "$source" "$filesystem" "$options" \
    >>"$tmp_inventory"

  remote=false
  case "$filesystem" in
    nfs|nfs4|cifs|smb3|sshfs|fuse.sshfs|ceph|glusterfs)
      remote=true
      remote_count=$((remote_count + 1))
      ;;
  esac

  case "$target" in
    /tmp|/var/tmp|/dev/shm)
      has_option "$options" noexec || add_finding MEDIUM "$target" 'temporary filesystem allows executable content'
      has_option "$options" nosuid || add_finding HIGH "$target" 'temporary filesystem does not disable SUID/SGID behavior'
      has_option "$options" nodev || add_finding MEDIUM "$target" 'temporary filesystem does not disable device files'
      ;;
  esac

  if [[ $remote == true ]]; then
    has_option "$options" noexec || add_finding MEDIUM "$target" "remote $filesystem mount allows executable content"
    has_option "$options" nosuid || add_finding HIGH "$target" "remote $filesystem mount does not disable SUID/SGID behavior"
    has_option "$options" nodev || add_finding MEDIUM "$target" "remote $filesystem mount does not disable device files"
  fi

  if [[ $target == /boot || $target == /boot/efi ]]; then
    if has_option "$options" rw; then
      add_finding MEDIUM "$target" 'boot filesystem is mounted read-write'
    fi
  fi
done <"$tmp_raw"

if (( mount_count == 0 )); then
  printf 'No mount records were found in the input.\n' >&2
  exit 2
fi

{
  printf 'Mounted Filesystem Security Inventory\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Source: %s\n' "$source_description"
  printf 'Mounts inspected: %d\n' "$mount_count"
  printf 'Remote mounts: %d\n' "$remote_count"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Mount inventory ==\n'
  awk -F'\t' '{print "target=" $1 " | source=" $2 " | type=" $3 " | options=" $4}' \
    "$tmp_inventory"

  printf '\n== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No configured mount-option risks were identified.\n'
  else
    sort -t $'\t' -k1,1 -k2,2 "$tmp_findings" \
      | awk -F'\t' '{print $1 " | " $2 " | " $3}'
  fi

  printf '\n== Analyst guidance ==\n'
  printf 'Validate findings against application requirements and the persistent mount configuration.\n'
  printf 'Review /etc/fstab or systemd mount units before planning any remount or reboot.\n'
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
