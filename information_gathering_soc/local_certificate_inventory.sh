#!/usr/bin/env bash
# Inventory local X.509 certificate files without making network connections.
#
# Examples:
#   sudo ./local_certificate_inventory.sh
#   ./local_certificate_inventory.sh -d /etc/nginx/certs -w 45
#   ./local_certificate_inventory.sh -d ./certificates -o cert-inventory.txt

set -uo pipefail
umask 077

search_root="/etc/ssl/certs"
warning_days=30
output_file=""

usage() {
  cat <<'EOF'
Usage: local_certificate_inventory.sh [OPTIONS]

Recursively inspect local .pem, .crt, and .cer files and report certificate
subjects, issuers, validity dates, SHA-256 fingerprints, and expiry status.

Options:
  -d DIR    Directory to inspect (default: /etc/ssl/certs).
  -w DAYS   Warn when expiry is within DAYS (default: 30).
  -o FILE   Save the report with mode 600 instead of printing it.
  -h        Show this help.

The script is read-only and does not contact certificate authorities or hosts.
Run with sudo if the certificate directory has restricted permissions.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':d:w:o:h' option; do
  case "$option" in
    d) search_root=$OPTARG ;;
    w) warning_days=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die "Unexpected argument: $1"
[[ -d $search_root ]] || die "Certificate directory does not exist: $search_root"
[[ -r $search_root ]] || die "Certificate directory is not readable: $search_root"
[[ $warning_days =~ ^[0-9]+$ ]] || die "DAYS must be a non-negative integer."

for command_name in openssl find date sort; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/certificate-inventory.XXXXXX") || die "Could not create temporary directory."
inventory_file="$work_dir/inventory.tsv"
invalid_file="$work_dir/invalid.txt"
errors_file="$work_dir/find-errors.txt"
report_file="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

: >"$inventory_file"
: >"$invalid_file"
now_epoch=$(date +%s)

while IFS= read -r -d '' certificate; do
  if ! openssl x509 -in "$certificate" -noout >/dev/null 2>&1; then
    printf '%q\n' "$certificate" >>"$invalid_file"
    continue
  fi

  subject=$(openssl x509 -in "$certificate" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
  issuer=$(openssl x509 -in "$certificate" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
  not_before=$(openssl x509 -in "$certificate" -noout -startdate | sed 's/^notBefore=//')
  not_after=$(openssl x509 -in "$certificate" -noout -enddate | sed 's/^notAfter=//')
  fingerprint=$(openssl x509 -in "$certificate" -noout -fingerprint -sha256 | sed 's/^sha256 Fingerprint=//')
  expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null || printf '0')
  seconds_left=$((expiry_epoch - now_epoch))
  days_left=$((seconds_left / 86400))

  if (( seconds_left < 0 )); then
    status="EXPIRED"
  elif (( seconds_left <= warning_days * 86400 )); then
    status="WARNING"
  else
    status="OK"
  fi

  printf '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%q\n' \
    "$days_left" "$status" "$not_before" "$not_after" "$subject" "$issuer" \
    "$fingerprint" "$certificate" >>"$inventory_file"
done < <(find "$search_root" -type f \
  \( -iname '*.pem' -o -iname '*.crt' -o -iname '*.cer' \) \
  -print0 2>"$errors_file")

certificate_count=$(wc -l <"$inventory_file")
invalid_count=$(wc -l <"$invalid_file")
scan_error_count=$(wc -l <"$errors_file")
expired_count=$(awk -F '\t' '$2 == "EXPIRED" {count++} END {print count + 0}' "$inventory_file")
warning_count=$(awk -F '\t' '$2 == "WARNING" {count++} END {print count + 0}' "$inventory_file")
ok_count=$(awk -F '\t' '$2 == "OK" {count++} END {print count + 0}' "$inventory_file")

{
  printf 'Local X.509 Certificate Inventory\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Search root: %s\n' "$(realpath -- "$search_root" 2>/dev/null || printf '%s' "$search_root")"
  printf 'Warning threshold: %s days\n\n' "$warning_days"

  printf 'Summary\n'
  printf 'Valid certificates: %s\n' "$certificate_count"
  printf 'OK: %s\n' "$ok_count"
  printf 'Warning: %s\n' "$warning_count"
  printf 'Expired: %s\n' "$expired_count"
  printf 'Invalid certificate files: %s\n' "$invalid_count"
  printf 'Directory scan errors: %s\n\n' "$scan_error_count"

  printf 'Certificates (soonest expiry first)\n'
  if [[ -s $inventory_file ]]; then
    sort -t $'\t' -k1,1n "$inventory_file" |
      while IFS=$'\t' read -r days status not_before not_after subject issuer fingerprint path; do
        printf '\n[%s] %s\n' "$status" "$path"
        printf '  Subject: %s\n' "$subject"
        printf '  Issuer: %s\n' "$issuer"
        printf '  Valid from: %s\n' "$not_before"
        printf '  Valid until: %s\n' "$not_after"
        printf '  Whole days remaining: %s\n' "$days"
        printf '  SHA-256 fingerprint: %s\n' "$fingerprint"
      done
  else
    printf 'None found.\n'
  fi

  printf '\nInvalid or non-certificate files with certificate extensions\n'
  [[ -s $invalid_file ]] && cat "$invalid_file" || printf 'None found.\n'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report_file" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report_file"
fi
