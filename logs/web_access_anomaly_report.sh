#!/usr/bin/env bash
# Summarize Apache/Nginx access logs and highlight likely reconnaissance.
# Supports common/combined log format and plain or gzip-compressed files.
#
# Examples:
#   ./web_access_anomaly_report.sh -f /var/log/nginx/access.log
#   ./web_access_anomaly_report.sh -f /var/log/httpd/access_log -n 25
#   ./web_access_anomaly_report.sh -f access.log.1.gz -o web-report.txt
#
# Exit codes: 0 no highlighted events, 1 review findings present, 2 input error.

set -uo pipefail
umask 077

log_file=""
top_count=15
output=""

usage() {
  cat <<'USAGE'
Usage: web_access_anomaly_report.sh -f LOG_FILE [-n COUNT] [-o REPORT]

Options:
  -f LOG_FILE  Apache/Nginx common or combined access log (.gz supported)
  -n COUNT     Number of top clients and paths to show (default: 15)
  -o REPORT    Save the report with permissions set to 600
  -h           Show this help

The script is read-only. Findings indicate events to review, not confirmed
compromise. Correlate flagged requests with application and authentication logs.
USAGE
}

while getopts ":f:n:o:h" option; do
  case "$option" in
    f) log_file=$OPTARG ;;
    n) top_count=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

if [[ -z $log_file ]]; then
  printf 'A log file is required.\n' >&2
  usage >&2
  exit 2
fi
if [[ ! -r $log_file ]]; then
  printf 'Log file is not readable: %s\n' "$log_file" >&2
  exit 2
fi
if [[ ! $top_count =~ ^[1-9][0-9]*$ ]]; then
  printf 'COUNT must be a positive integer.\n' >&2
  exit 2
fi

tmp_input=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_input" "$tmp_report"' EXIT

if [[ $log_file == *.gz ]]; then
  if ! command -v gzip >/dev/null 2>&1; then
    printf 'gzip is required to read compressed logs.\n' >&2
    exit 2
  fi
  if ! gzip -cd -- "$log_file" >"$tmp_input"; then
    printf 'Unable to decompress log file: %s\n' "$log_file" >&2
    exit 2
  fi
else
  cp -- "$log_file" "$tmp_input"
fi

awk -F'"' -v limit="$top_count" -v source="$log_file" '
  function add_sample(text) {
    if (sample_count < 20) {
      sample_count++
      samples[sample_count] = text
    }
  }
  function top_table(values, labels, heading,    key, count, i, best_key, best) {
    print ""
    print "== " heading " =="
    count = 0
    for (key in values) count++
    if (count == 0) {
      print "None found."
      return
    }
    for (i = 1; i <= limit && i <= count; i++) {
      best = -1
      best_key = ""
      for (key in values) {
        if (values[key] > best) {
          best = values[key]
          best_key = key
        }
      }
      printf "%8d  %s%s\n", best, (labels ? labels : ""), best_key
      delete values[best_key]
    }
  }
  BEGIN {
    print "Web Access Log Anomaly Report"
    print "Source: " source
  }
  {
    total++
    split($1, prefix, " ")
    client = prefix[1]
    request = $2
    split($3, suffix, " ")
    status = suffix[1]

    split(request, request_parts, " ")
    method = request_parts[1]
    path = request_parts[2]

    if (client == "" || request == "" || status !~ /^[0-9][0-9][0-9]$/) {
      malformed++
      next
    }

    parsed++
    clients[client]++
    statuses[status]++
    paths[path]++

    if (status ~ /^5/) {
      server_errors++
      add_sample("[SERVER ERROR] " client " " status " " method " " path)
    }
    if (status ~ /^4/) client_errors++

    lower_path = tolower(path)
    if (lower_path ~ /(^|\/)(\.env|\.git|wp-admin|wp-login\.php|phpmyadmin|xmlrpc\.php)(\/|\?|$)/ ||
        lower_path ~ /(etc\/passwd|\.\.\/|cgi-bin|vendor\/phpunit|server-status)/) {
      suspicious++
      suspicious_clients[client]++
      suspicious_paths[path]++
      add_sample("[RECON PATH] " client " " status " " method " " path)
    }
  }
  END {
    print "Total lines: " total
    print "Parsed requests: " parsed
    print "Malformed/unrecognized lines: " malformed + 0
    print "4xx responses: " client_errors + 0
    print "5xx responses: " server_errors + 0
    print "Recon-path requests: " suspicious + 0

    top_table(clients, "", "Top client addresses")

    print ""
    print "== Response status counts =="
    status_count = 0
    for (code in statuses) status_count++
    if (status_count == 0) print "None found."
    for (i = 1; i <= status_count; i++) {
      best = -1
      best_code = ""
      for (code in statuses) {
        if (statuses[code] > best) {
          best = statuses[code]
          best_code = code
        }
      }
      printf "%8d  HTTP %s\n", best, best_code
      delete statuses[best_code]
    }

    top_table(paths, "", "Top requested paths")
    top_table(suspicious_clients, "", "Clients requesting recon paths")
    top_table(suspicious_paths, "", "Recon paths requested")

    print ""
    print "== Review samples (maximum 20) =="
    if (sample_count == 0) print "None found."
    for (i = 1; i <= sample_count; i++) print samples[i]

    print ""
    print "== Assessment =="
    if ((server_errors + suspicious) > 0) {
      print "Review recommended: correlate highlighted requests with application, WAF, and authentication events."
    } else {
      print "No server errors or known reconnaissance paths were detected."
    }
  }
' "$tmp_input" >"$tmp_report"

finding_count=$(awk -F': ' '
  /^5xx responses:/ {n += $2}
  /^Recon-path requests:/ {n += $2}
  END {print n + 0}
' "$tmp_report")

if [[ -n $output ]]; then
  cp -- "$tmp_report" "$output"
  chmod 600 "$output"
  printf 'Report written to %s\n' "$output"
else
  cat "$tmp_report"
fi

(( finding_count == 0 )) && exit 0
exit 1
