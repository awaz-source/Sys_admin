#!/usr/bin/env bash
# Hunt Linux SSH authentication logs for brute force and suspicious successes.
# Read-only: this script never blocks addresses or changes SSH configuration.
#
# Examples:
#   sudo ./ssh_authentication_hunt.sh
#   ./ssh_authentication_hunt.sh -i /var/log/auth.log -t 10
#   ./ssh_authentication_hunt.sh -i archived-secure.log.gz -o ssh-hunt.txt
#   sudo ./ssh_authentication_hunt.sh -s '24 hours ago'
#
# Exit codes: 0 hunt completed, 2 invalid input or collection failure.

set -uo pipefail
umask 077

input=""
output=""
since="24 hours ago"
threshold=10

usage() {
  cat <<'USAGE'
Usage: ssh_authentication_hunt.sh [-i LOG] [-s SINCE] [-t COUNT] [-o REPORT]

Options:
  -i LOG     Read an auth/secure log or .gz archive instead of live data
  -s SINCE   journalctl time expression for live collection (default: 24 hours ago)
  -t COUNT   Failed attempts from one source that trigger HIGH (default: 10)
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

Without -i, the script queries ssh/sshd journal units, then falls back to a
readable /var/log/auth.log or /var/log/secure. It recognizes common OpenSSH
Failed password, Invalid user, and Accepted authentication messages. Findings
are leads for investigation and should be compared with approved access.
USAGE
}

while getopts ":i:s:t:o:h" option; do
  case "$option" in
    i) input=$OPTARG ;;
    s) since=$OPTARG ;;
    t) threshold=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ ! $threshold =~ ^[1-9][0-9]*$ ]]; then
  printf 'COUNT must be a positive integer.\n' >&2
  exit 2
fi
if [[ -n $input && ! -r $input ]]; then
  printf 'Input log is not readable: %s\n' "$input" >&2
  exit 2
fi

tmp_raw=$(mktemp)
tmp_failed=$(mktemp)
tmp_invalid=$(mktemp)
tmp_success=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_raw" "$tmp_failed" "$tmp_invalid" "$tmp_success" "$tmp_findings" "$tmp_report"' EXIT

source_description=""
if [[ -n $input ]]; then
  source_description=$input
  if [[ $input == *.gz ]]; then
    command -v gzip >/dev/null 2>&1 || {
      printf 'gzip is required to read: %s\n' "$input" >&2
      exit 2
    }
    gzip -cd -- "$input" >"$tmp_raw" || {
      printf 'Unable to decompress input log: %s\n' "$input" >&2
      exit 2
    }
  else
    cp -- "$input" "$tmp_raw" || exit 2
  fi
elif command -v journalctl >/dev/null 2>&1; then
  source_description="journalctl ssh/sshd since $since"
  journalctl --no-pager --since "$since" -u ssh.service -u sshd.service \
    >"$tmp_raw" 2>/dev/null || {
      printf 'Unable to query the system journal. Try sudo or provide -i LOG.\n' >&2
      exit 2
    }
else
  for candidate in /var/log/auth.log /var/log/secure; do
    if [[ -r $candidate ]]; then
      input=$candidate
      source_description=$candidate
      cp -- "$candidate" "$tmp_raw" || exit 2
      break
    fi
  done
  [[ -n $source_description ]] || {
    printf 'No journalctl or readable SSH authentication log was found.\n' >&2
    exit 2
  }
fi

while IFS= read -r line || [[ -n $line ]]; do
  if [[ $line =~ Failed[[:space:]]password[[:space:]]for[[:space:]](invalid[[:space:]]user[[:space:]])?([^[:space:]]+)[[:space:]]from[[:space:]]([0-9A-Fa-f:.]+) ]]; then
    user=${BASH_REMATCH[2]}
    address=${BASH_REMATCH[3]}
    printf '%s|%s|%s\n' "$address" "$user" "$line" >>"$tmp_failed"
  elif [[ $line =~ Invalid[[:space:]]user[[:space:]]([^[:space:]]+)[[:space:]]from[[:space:]]([0-9A-Fa-f:.]+) ]]; then
    user=${BASH_REMATCH[1]}
    address=${BASH_REMATCH[2]}
    printf '%s|%s|%s\n' "$address" "$user" "$line" >>"$tmp_invalid"
  fi

  if [[ $line =~ Accepted[[:space:]]([^[:space:]]+)[[:space:]]for[[:space:]]([^[:space:]]+)[[:space:]]from[[:space:]]([0-9A-Fa-f:.]+) ]]; then
    method=${BASH_REMATCH[1]}
    user=${BASH_REMATCH[2]}
    address=${BASH_REMATCH[3]}
    printf '%s|%s|%s|%s\n' "$address" "$user" "$method" "$line" >>"$tmp_success"
  fi
done <"$tmp_raw"

failed_count=$(awk 'END {print NR + 0}' "$tmp_failed")
invalid_count=$(awk 'END {print NR + 0}' "$tmp_invalid")
success_count=$(awk 'END {print NR + 0}' "$tmp_success")
finding_count=0

add_finding() {
  local severity=$1 subject=$2 reason=$3
  printf '%s | %s | %s\n' "$severity" "$subject" "$reason" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
}

while IFS='|' read -r count address; do
  [[ -n $address ]] || continue
  if (( count >= threshold )); then
    add_finding HIGH "$address" "$count failed SSH password attempts (threshold $threshold)"
  fi
done < <(cut -d'|' -f1 "$tmp_failed" | sort | uniq -c | awk '{print $1 "|" $2}')

while IFS='|' read -r address user method _rest; do
  [[ -n $address ]] || continue
  if [[ $user == root ]]; then
    add_finding HIGH "$address" "successful SSH login as root using $method"
  fi
  if [[ $method == password || $method == keyboard-interactive* ]]; then
    add_finding MEDIUM "$address" "successful password-based SSH login for $user"
  fi
  if awk -F'|' -v ip="$address" '$1 == ip {found=1} END {exit !found}' "$tmp_failed"; then
    add_finding HIGH "$address" "successful login for $user after failures from the same source"
  fi
done <"$tmp_success"

{
  printf 'SSH Authentication Threat Hunt\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Source: %s\n' "$source_description"
  printf 'Failure threshold: %d\n' "$threshold"
  printf 'Failed passwords: %d\n' "$failed_count"
  printf 'Standalone invalid-user events: %d\n' "$invalid_count"
  printf 'Successful authentications: %d\n' "$success_count"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Failed attempts by source ==\n'
  if (( failed_count == 0 )); then
    printf 'No failed-password events matched.\n'
  else
    cut -d'|' -f1 "$tmp_failed" | sort | uniq -c | sort -nr | awk '{print $1 " | " $2}'
  fi

  printf '\n== Targeted usernames ==\n'
  if (( failed_count + invalid_count == 0 )); then
    printf 'No targeted usernames matched.\n'
  else
    { cut -d'|' -f2 "$tmp_failed"; cut -d'|' -f2 "$tmp_invalid"; } \
      | sort | uniq -c | sort -nr | awk '{print $1 " | " $2}'
  fi

  printf '\n== Successful authentications ==\n'
  if (( success_count == 0 )); then
    printf 'No successful SSH authentication events matched.\n'
  else
    awk -F'|' '{print $1 " | user=" $2 " | method=" $3}' "$tmp_success"
  fi

  printf '\n== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No configured hunt conditions were triggered.\n'
  else
    sort -t '|' -k1,1 -k2,2 "$tmp_findings"
  fi

  printf '\n== Analyst guidance ==\n'
  printf 'Validate source addresses, user activity, MFA/VPN context, and maintenance windows.\n'
  printf 'Correlate suspicious successes with process, sudo, network, and file telemetry.\n'
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

exit 0
