#!/usr/bin/env bash
# Summarize OpenSSH authentication activity from journald or a log file.
#
# Examples:
#   sudo ./ssh_auth_summary.sh
#   sudo ./ssh_auth_summary.sh -s "7 days ago" -n 30
#   ./ssh_auth_summary.sh -f /var/log/auth.log -o ssh-auth-report.txt
#   ./ssh_auth_summary.sh -f /var/log/secure

set -uo pipefail
umask 077

since="24 hours ago"
max_results=20
input_file=""
output_file=""

usage() {
  cat <<'EOF'
Usage: ssh_auth_summary.sh [-f LOG_FILE] [-s SINCE] [-n COUNT] [-o REPORT]

Create a read-only summary of successful and unsuccessful OpenSSH logins.

Options:
  -f FILE   Read FILE instead of the systemd journal (for example,
            /var/log/auth.log or /var/log/secure). Use /dev/stdin for a pipe.
  -s TIME   Journal start time accepted by journalctl (default: 24 hours ago).
  -n COUNT  Maximum rows in each top/recent section (default: 20).
  -o FILE   Save the report with permissions 600 instead of printing it.
  -h        Show this help.

Reading the system journal or protected log files may require sudo.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':f:s:n:o:h' option; do
  case "$option" in
    f) input_file=$OPTARG ;;
    s) since=$OPTARG ;;
    n) max_results=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die "Unexpected argument: $1"
[[ $max_results =~ ^[1-9][0-9]*$ ]] || die "COUNT must be a positive integer."

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ssh-auth-summary.XXXXXX") || die "Cannot create temporary directory."
raw_log="$work_dir/ssh.log"
report="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

if [[ -n $input_file ]]; then
  [[ -r $input_file ]] || die "Cannot read log file: $input_file"
  cp -- "$input_file" "$raw_log" || die "Could not copy log input."
  source_description=$input_file
else
  command -v journalctl >/dev/null 2>&1 || die "journalctl is required when -f is not used."
  journalctl --unit sshd --unit ssh --since "$since" --no-pager --output short-iso >"$raw_log" ||
    die "Could not read the SSH journal (try running with sudo)."
  source_description="systemd journal since $since"
fi

count_matching() {
  local expression=$1
  awk -v pattern="$expression" 'tolower($0) ~ pattern { count++ } END { print count + 0 }' "$raw_log"
}

top_sources() {
  local expression=$1
  awk -v pattern="$expression" '
    tolower($0) ~ pattern {
      ip = ""
      for (i = 1; i <= NF; i++) {
        if ($i == "from" && (i + 1) <= NF) ip = $(i + 1)
        if ($i ~ /^rhost=/) { split($i, value, "="); ip = value[2] }
      }
      if (ip != "") print ip
    }
  ' "$raw_log" | sort | uniq -c | sort -k1,1nr -k2,2 | head -n "$max_results"
}

failed_count=$(count_matching 'failed password')
accepted_count=$(count_matching 'accepted (password|publickey)')
invalid_count=$(count_matching 'invalid user')

{
  printf 'OpenSSH Authentication Summary\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Source: %s\n\n' "$source_description"

  printf 'Event counts\n'
  printf '  Failed password events: %s\n' "$failed_count"
  printf '  Accepted authentication events: %s\n' "$accepted_count"
  printf '  Invalid user events: %s\n\n' "$invalid_count"

  printf 'Top unsuccessful source addresses\n'
  unsuccessful=$(top_sources 'failed password|invalid user|authentication failure')
  [[ -n $unsuccessful ]] && printf '%s\n' "$unsuccessful" || printf '  None.\n'
  printf '\nTop successful source addresses\n'
  successful=$(top_sources 'accepted (password|publickey)')
  [[ -n $successful ]] && printf '%s\n' "$successful" || printf '  None.\n'

  printf '\nMost recent authentication events\n'
  recent=$(awk 'tolower($0) ~ /failed password|accepted (password|publickey)|invalid user|authentication failure/' "$raw_log" | tail -n "$max_results")
  [[ -n $recent ]] && printf '%s\n' "$recent" || printf '  None.\n'
} >"$report"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report"
fi
