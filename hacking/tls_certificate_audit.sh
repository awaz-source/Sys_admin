#!/usr/bin/env bash
# Inspect the TLS certificate presented by one authorized host and port.
# This performs a single TLS handshake; it does not scan ports or exploit hosts.
#
# Examples:
#   ./tls_certificate_audit.sh example.com
#   ./tls_certificate_audit.sh -p 8443 -d 30 -o tls-report.txt app.lab.local

set -uo pipefail
umask 077

port=443
warning_days=30
timeout_seconds=10
output_file=""

usage() {
  cat <<'EOF'
Usage: tls_certificate_audit.sh [OPTIONS] HOST

Perform one defensive TLS handshake and report certificate identity, issuer,
validity, fingerprints, negotiated protocol/cipher, and expiry status.

Options:
  -p PORT    TLS port (default: 443).
  -d DAYS    Warn when the certificate expires within DAYS (default: 30).
  -t SEC     Connection timeout in seconds (default: 10).
  -o FILE    Save the report with mode 600 instead of printing it.
  -h         Show this help.

Only test systems you own or are explicitly authorized to assess.
Requires: openssl, timeout, awk, date.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':p:d:t:o:h' option; do
  case "$option" in
    p) port=$OPTARG ;;
    d) warning_days=$OPTARG ;;
    t) timeout_seconds=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 1 )) || die "Specify exactly one host."
host=$1
[[ $host =~ ^[A-Za-z0-9._:-]+$ ]] || die "HOST contains unsupported characters."
[[ $port =~ ^[0-9]+$ ]] && (( port >= 1 && port <= 65535 )) || die "PORT must be between 1 and 65535."
[[ $warning_days =~ ^[0-9]+$ ]] || die "DAYS must be a non-negative integer."
[[ $timeout_seconds =~ ^[1-9][0-9]*$ ]] || die "SEC must be a positive integer."

for command_name in openssl timeout awk date; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/tls-audit.XXXXXX") || die "Could not create temporary directory."
handshake_file="$work_dir/handshake.txt"
certificate_file="$work_dir/certificate.pem"
report_file="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

if ! timeout "$timeout_seconds" openssl s_client \
  -connect "${host}:${port}" -servername "$host" -showcerts \
  </dev/null >"$handshake_file" 2>&1; then
  grep -q -- '-----BEGIN CERTIFICATE-----' "$handshake_file" ||
    die "TLS connection failed or timed out: ${host}:${port}"
fi

awk '/-----BEGIN CERTIFICATE-----/{capture=1} capture{print} /-----END CERTIFICATE-----/{exit}' \
  "$handshake_file" >"$certificate_file"
openssl x509 -in "$certificate_file" -noout >/dev/null 2>&1 || die "The server did not return a valid X.509 certificate."

subject=$(openssl x509 -in "$certificate_file" -noout -subject -nameopt RFC2253 | sed 's/^subject=//')
issuer=$(openssl x509 -in "$certificate_file" -noout -issuer -nameopt RFC2253 | sed 's/^issuer=//')
serial=$(openssl x509 -in "$certificate_file" -noout -serial | sed 's/^serial=//')
not_before=$(openssl x509 -in "$certificate_file" -noout -startdate | sed 's/^notBefore=//')
not_after=$(openssl x509 -in "$certificate_file" -noout -enddate | sed 's/^notAfter=//')
sha256_fp=$(openssl x509 -in "$certificate_file" -noout -fingerprint -sha256 | sed 's/^sha256 Fingerprint=//')
san=$(openssl x509 -in "$certificate_file" -noout -ext subjectAltName 2>/dev/null | awk 'NR > 1 {gsub(/^[[:space:]]+/, ""); printf "%s%s", separator, $0; separator=" "}')
[[ -n $san ]] || san="Not present"

expiry_epoch=$(date -d "$not_after" +%s 2>/dev/null) || die "Could not parse certificate expiry date."
now_epoch=$(date +%s)
seconds_left=$((expiry_epoch - now_epoch))
days_left=$((seconds_left / 86400))
if (( seconds_left < 0 )); then
  expiry_status="FAIL - certificate has expired"
elif (( seconds_left <= warning_days * 86400 )); then
  expiry_status="WARN - expires within ${warning_days} days"
else
  expiry_status="PASS - more than ${warning_days} days remain"
fi

if openssl x509 -in "$certificate_file" -noout -checkhost "$host" >/dev/null 2>&1; then
  hostname_status="PASS - certificate matches $host"
else
  hostname_status="FAIL - certificate does not match $host"
fi

protocol=$(awk -F': *' '/^[[:space:]]*Protocol *:/{print $2; exit}' "$handshake_file")
cipher=$(awk -F': *' '/^[[:space:]]*Cipher *:/{print $2; exit}' "$handshake_file")
[[ -n $protocol ]] || protocol="Unknown"
[[ -n $cipher ]] || cipher="Unknown"

{
  printf 'TLS Certificate Audit\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Target: %s:%s\n\n' "$host" "$port"
  printf 'Subject: %s\n' "$subject"
  printf 'Issuer: %s\n' "$issuer"
  printf 'Serial: %s\n' "$serial"
  printf 'Subject alternative names: %s\n' "$san"
  printf 'Valid from: %s\n' "$not_before"
  printf 'Valid until: %s\n' "$not_after"
  printf 'Whole days remaining: %s\n' "$days_left"
  printf 'SHA-256 fingerprint: %s\n\n' "$sha256_fp"
  printf 'Negotiated protocol: %s\n' "$protocol"
  printf 'Negotiated cipher: %s\n\n' "$cipher"
  printf 'Hostname check: %s\n' "$hostname_status"
  printf 'Expiry check: %s\n' "$expiry_status"
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report_file" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report_file"
fi
