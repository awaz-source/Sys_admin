#!/usr/bin/env bash
# Read-only hunt for suspicious characteristics in currently running processes.
# Findings are leads for analyst review, not automatic proof of compromise.
#
# Examples:
#   sudo ./process_anomaly_hunt.sh
#   sudo ./process_anomaly_hunt.sh -n 30 -o process-hunt.txt

set -uo pipefail
umask 077

max_rows=25
output_file=""

usage() {
  cat <<'EOF'
Usage: process_anomaly_hunt.sh [-n COUNT] [-o REPORT]

Hunt the local Linux host for running deleted executables, processes launched
from temporary paths, deleted working directories, suspicious command patterns,
high-resource processes, and process-associated network sockets.

Options:
  -n COUNT   Maximum rows per report section (default: 25).
  -o FILE    Save the report with mode 600 instead of printing it.
  -h         Show this help.

Run with sudo for the most complete /proc and socket visibility. The script is
read-only and does not stop processes, delete files, or alter the host.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':n:o:h' option; do
  case "$option" in
    n) max_rows=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die "Unexpected argument: $1"
[[ $max_rows =~ ^[1-9][0-9]*$ ]] || die "COUNT must be a positive integer."
[[ -d /proc ]] || die "/proc is required."
for command_name in ps awk sort head readlink; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/process-hunt.XXXXXX") || die "Could not create temporary directory."
deleted_exe_file="$work_dir/deleted-executables.txt"
temp_exe_file="$work_dir/temporary-executables.txt"
deleted_cwd_file="$work_dir/deleted-working-directories.txt"
report_file="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

: >"$deleted_exe_file"
: >"$temp_exe_file"
: >"$deleted_cwd_file"

for process_dir in /proc/[0-9]*; do
  [[ -d $process_dir ]] || continue
  pid=${process_dir##*/}
  executable=$(readlink "$process_dir/exe" 2>/dev/null || true)
  working_dir=$(readlink "$process_dir/cwd" 2>/dev/null || true)
  command_line=$(tr '\0' ' ' <"$process_dir/cmdline" 2>/dev/null || true)
  [[ -n $command_line ]] || command_line="[$(cat "$process_dir/comm" 2>/dev/null || printf unknown)]"

  if [[ $executable == *' (deleted)' ]]; then
    printf 'PID=%s EXE=%q CMD=%q\n' "$pid" "$executable" "$command_line" >>"$deleted_exe_file"
  fi
  case "$executable" in
    /tmp/*|/var/tmp/*|/dev/shm/*)
      printf 'PID=%s EXE=%q CMD=%q\n' "$pid" "$executable" "$command_line" >>"$temp_exe_file"
      ;;
  esac
  if [[ $working_dir == *' (deleted)' ]]; then
    printf 'PID=%s CWD=%q CMD=%q\n' "$pid" "$working_dir" "$command_line" >>"$deleted_cwd_file"
  fi
done

print_file_section() {
  local path=$1
  if [[ -s $path ]]; then
    head -n "$max_rows" "$path"
  else
    printf 'None found.\n'
  fi
}

{
  printf 'Linux Process Anomaly Hunt\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Visibility: %s\n\n' "$([[ $EUID -eq 0 ]] && printf root || printf non-root)"

  printf 'Running deleted executables\n'
  print_file_section "$deleted_exe_file"
  printf '\nExecutables launched from temporary paths\n'
  print_file_section "$temp_exe_file"
  printf '\nProcesses with deleted working directories\n'
  print_file_section "$deleted_cwd_file"

  printf '\nCommands requiring analyst review\n'
  suspicious=$(ps axww -o pid=,user=,args= | awk '
    {
      line=tolower($0)
      if (line ~ /(curl|wget).*[|].*(sh|bash)/ ||
          line ~ /base64[[:space:]].*(-d|--decode)/ ||
          line ~ /(nc|ncat|netcat).*(-e|--exec)/ ||
          line ~ /python[^ ]*.*(pty|socket).*spawn/) print
    }
  ' | head -n "$max_rows")
  [[ -n $suspicious ]] && printf '%s\n' "$suspicious" || printf 'None found.\n'

  printf '\nHighest CPU processes\n'
  ps axww -o pid=,user=,%cpu=,%mem=,etime=,comm= --sort=-%cpu | head -n "$max_rows"
  printf '\nHighest memory processes\n'
  ps axww -o pid=,user=,%cpu=,%mem=,etime=,comm= --sort=-%mem | head -n "$max_rows"

  printf '\nProcess-associated network sockets\n'
  if command -v ss >/dev/null 2>&1; then
    sockets=$(ss -tunap 2>/dev/null | awk 'NR == 1 || /users:\(\(/' | head -n "$max_rows")
    [[ -n $sockets ]] && printf '%s\n' "$sockets" || printf 'None visible.\n'
  else
    printf 'Not collected: ss command is unavailable.\n'
  fi

  printf '\nReview guidance\n'
  printf '%s\n' '- Confirm the parent process, user, start time, and expected owner.'
  printf '%s\n' '- Preserve volatile evidence before terminating a suspicious process.'
  printf '%s\n' '- Correlate findings with authentication, endpoint, and network logs.'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report_file" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report_file"
fi
