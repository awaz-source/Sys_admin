#!/usr/bin/env bash
# Create and verify SHA-256 baselines for important configuration files.
# Baseline creation is explicit; check mode never modifies monitored files.
#
# Examples:
#   sudo ./config_drift_report.sh create /root/etc-baseline.tsv /etc/ssh /etc/sudoers
#   sudo ./config_drift_report.sh create -f /root/etc-baseline.tsv /etc/ssh
#   sudo ./config_drift_report.sh check /root/etc-baseline.tsv
#   sudo ./config_drift_report.sh check -o drift-report.txt /root/etc-baseline.tsv
#
# Exit codes: 0 success/no drift, 1 drift detected, 2 usage or collection error.

set -uo pipefail
umask 077

usage() {
  cat <<'USAGE'
Usage:
  config_drift_report.sh create [-f] MANIFEST PATH...
  config_drift_report.sh check [-o REPORT] MANIFEST

Commands:
  create   Record SHA-256, mode, owner, and group for files under PATH
  check    Compare current files with a previously created manifest

Options:
  -f         Replace an existing manifest (create only)
  -o REPORT  Save the check report with permissions set to 600
  -h         Show this help

Directories are traversed recursively without following symbolic links. Paths
containing tabs or newlines are rejected because the manifest is tab-delimited.
Protect the manifest as evidence and store it separately from monitored files.
USAGE
}

[[ $# -gt 0 ]] || { usage >&2; exit 2; }
command_name=$1
shift

require_command() {
  command -v "$1" >/dev/null 2>&1 || {
    printf 'Required command was not found: %s\n' "$1" >&2
    exit 2
  }
}

require_command sha256sum
require_command stat
require_command realpath

create_manifest() {
  local force=no
  local option manifest manifest_dir tmp_manifest tmp_paths

  OPTIND=1
  while getopts ":fh" option; do
    case "$option" in
      f) force=yes ;;
      h) usage; exit 0 ;;
      :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
      \?) printf 'Unknown create option: -%s\n' "$OPTARG" >&2; exit 2 ;;
    esac
  done
  shift $((OPTIND - 1))

  (( $# >= 2 )) || { usage >&2; exit 2; }
  manifest=$1
  shift

  if [[ -e $manifest && $force != yes ]]; then
    printf 'Manifest already exists; use create -f to replace it: %s\n' "$manifest" >&2
    exit 2
  fi

  manifest_dir=$(dirname -- "$manifest")
  [[ -d $manifest_dir ]] || {
    printf 'Manifest directory was not found: %s\n' "$manifest_dir" >&2
    exit 2
  }

  tmp_manifest=$(mktemp "$manifest_dir/.config-drift-manifest.XXXXXX") || exit 2
  tmp_paths=$(mktemp) || { rm -f "$tmp_manifest"; exit 2; }
  trap 'rm -f "$tmp_manifest" "$tmp_paths"' RETURN

  local input
  for input in "$@"; do
    if [[ -f $input && ! -L $input ]]; then
      printf '%s\0' "$input" >>"$tmp_paths"
    elif [[ -d $input && ! -L $input ]]; then
      find "$input" -xdev -type f -print0 >>"$tmp_paths" || {
        printf 'Unable to enumerate directory: %s\n' "$input" >&2
        exit 2
      }
    else
      printf 'Path is not a regular file or directory: %s\n' "$input" >&2
      exit 2
    fi
  done

  printf '# config_drift_report manifest v1\n' >"$tmp_manifest"
  printf '# sha256\tmode\towner\tgroup\tpath\n' >>"$tmp_manifest"

  local path hash metadata mode owner group count=0
  while IFS= read -r -d '' path; do
    path=$(realpath -e -- "$path") || {
      printf 'Unable to resolve path: %s\n' "$path" >&2
      exit 2
    }
    if [[ $path == *$'\t'* || $path == *$'\n'* ]]; then
      printf 'Unsupported tab or newline in path: %q\n' "$path" >&2
      exit 2
    fi
    [[ -r $path ]] || { printf 'File is not readable: %s\n' "$path" >&2; exit 2; }
    hash=$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}') || exit 2
    metadata=$(stat -Lc '%a|%U|%G' -- "$path" 2>/dev/null) || exit 2
    IFS='|' read -r mode owner group <<<"$metadata"
    printf '%s\t%s\t%s\t%s\t%s\n' "$hash" "$mode" "$owner" "$group" "$path" >>"$tmp_manifest"
    count=$((count + 1))
  done < <(sort -zu "$tmp_paths")

  (( count > 0 )) || { printf 'No regular files were selected.\n' >&2; exit 2; }
  chmod 600 "$tmp_manifest"
  mv -f -- "$tmp_manifest" "$manifest"
  trap - RETURN
  rm -f "$tmp_paths"
  printf 'Created baseline for %d file(s): %s\n' "$count" "$manifest"
}

check_manifest() {
  local output="" option manifest tmp_findings tmp_report
  OPTIND=1
  while getopts ":o:h" option; do
    case "$option" in
      o) output=$OPTARG ;;
      h) usage; exit 0 ;;
      :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
      \?) printf 'Unknown check option: -%s\n' "$OPTARG" >&2; exit 2 ;;
    esac
  done
  shift $((OPTIND - 1))

  (( $# == 1 )) || { usage >&2; exit 2; }
  manifest=$1
  [[ -f $manifest && -r $manifest ]] || {
    printf 'Manifest is not a readable regular file: %s\n' "$manifest" >&2
    exit 2
  }

  tmp_findings=$(mktemp)
  tmp_report=$(mktemp)
  trap 'rm -f "$tmp_findings" "$tmp_report"' RETURN

  local expected_hash expected_mode expected_owner expected_group path
  local actual_hash actual_mode actual_owner actual_group metadata
  local checked=0 drift_count=0
  while IFS=$'\t' read -r expected_hash expected_mode expected_owner expected_group path; do
    [[ $expected_hash == \#* || -z $expected_hash ]] && continue
    if [[ ! $expected_hash =~ ^[0-9a-fA-F]{64}$ || -z $path ]]; then
      printf 'Malformed manifest entry near file record %d.\n' "$((checked + 1))" >&2
      exit 2
    fi
    checked=$((checked + 1))

    if [[ ! -f $path || -L $path ]]; then
      printf 'MISSING\t%s\tfile is absent or no longer a regular file\n' "$path" >>"$tmp_findings"
      drift_count=$((drift_count + 1))
      continue
    fi
    [[ -r $path ]] || {
      printf 'UNREADABLE\t%s\tunable to calculate current hash\n' "$path" >>"$tmp_findings"
      drift_count=$((drift_count + 1))
      continue
    }

    actual_hash=$(sha256sum -- "$path" 2>/dev/null | awk '{print $1}') || exit 2
    metadata=$(stat -Lc '%a|%U|%G' -- "$path" 2>/dev/null) || exit 2
    IFS='|' read -r actual_mode actual_owner actual_group <<<"$metadata"

    if [[ $actual_hash != "$expected_hash" ]]; then
      printf 'CONTENT\t%s\tSHA-256 changed\n' "$path" >>"$tmp_findings"
      drift_count=$((drift_count + 1))
    fi
    if [[ $actual_mode != "$expected_mode" ]]; then
      printf 'MODE\t%s\t%s -> %s\n' "$path" "$expected_mode" "$actual_mode" >>"$tmp_findings"
      drift_count=$((drift_count + 1))
    fi
    if [[ $actual_owner != "$expected_owner" || $actual_group != "$expected_group" ]]; then
      printf 'OWNERSHIP\t%s\t%s:%s -> %s:%s\n' "$path" "$expected_owner" "$expected_group" "$actual_owner" "$actual_group" >>"$tmp_findings"
      drift_count=$((drift_count + 1))
    fi
  done <"$manifest"

  (( checked > 0 )) || { printf 'Manifest contains no file records: %s\n' "$manifest" >&2; exit 2; }

  {
    printf 'Configuration Drift Report\n'
    printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
    printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
    printf 'Manifest: %s\n' "$manifest"
    printf 'Files checked: %d\n' "$checked"
    printf 'Drift findings: %d\n' "$drift_count"
    printf '\n== Findings ==\n'
    if (( drift_count == 0 )); then
      printf 'No content, mode, ownership, or missing-file drift detected.\n'
    else
      printf 'TYPE | PATH | DETAIL\n'
      sort -t $'\t' -k1,1 -k2,2 "$tmp_findings" | tr '\t' '|'
    fi
  } >"$tmp_report"

  if [[ -n $output ]]; then
    cp -- "$tmp_report" "$output" || exit 2
    chmod 600 "$output"
    printf 'Report written to %s\n' "$output"
  else
    cat "$tmp_report"
  fi

  (( drift_count == 0 )) && return 0
  return 1
}

case "$command_name" in
  create) create_manifest "$@" ;;
  check) check_manifest "$@" ;;
  -h|--help|help) usage ;;
  *) printf 'Unknown command: %s\n' "$command_name" >&2; usage >&2; exit 2 ;;
esac
