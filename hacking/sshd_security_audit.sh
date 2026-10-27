#!/usr/bin/env bash
# Read-only defensive audit of the effective OpenSSH server configuration.
# It does not change sshd, restart services, or connect to a remote system.
#
# Examples:
#   sudo ./sshd_security_audit.sh
#   sudo ./sshd_security_audit.sh -o sshd-audit.txt
#   sshd -T > effective-sshd.txt
#   ./sshd_security_audit.sh -f effective-sshd.txt

set -uo pipefail
umask 077

input_file=""
output_file=""

usage() {
  cat <<'EOF'
Usage: sshd_security_audit.sh [-f EFFECTIVE_CONFIG] [-o REPORT]

Review effective sshd settings for risky authentication, forwarding, and
cryptographic options. By default the script runs `sshd -T`; use -f to analyze
previously collected `sshd -T` output or to test a proposed effective config.

Options:
  -f FILE   Read effective sshd configuration from FILE.
  -o FILE   Save the report with mode 600 instead of printing it.
  -h        Show this help.

Run with sudo if sshd cannot read its host keys. Findings are hardening leads;
validate operational requirements before changing production configuration.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':f:o:h' option; do
  case "$option" in
    f) input_file=$OPTARG ;;
    o) output_file=$OPTARG ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die "Unexpected argument: $1"
for command_name in awk tr paste install; do
  command -v "$command_name" >/dev/null 2>&1 || die "Required command not found: $command_name"
done

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/sshd-security-audit.XXXXXX") || die "Could not create temporary directory."
effective_file="$work_dir/effective.conf"
findings_file="$work_dir/findings.tsv"
report_file="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

if [[ -n $input_file ]]; then
  [[ -f $input_file && -r $input_file ]] || die "Cannot read effective config: $input_file"
  awk 'NF >= 2 && $1 !~ /^#/ {key=tolower($1); $1=""; sub(/^[[:space:]]+/, ""); print key " " $0}' \
    "$input_file" >"$effective_file"
  source_description=$input_file
else
  command -v sshd >/dev/null 2>&1 || die "sshd is required when -f is not used."
  if ! sshd -T -C user=root,host=localhost,addr=127.0.0.1 >"$effective_file" 2>"$work_dir/sshd-error.txt"; then
    error_text=$(<"$work_dir/sshd-error.txt")
    die "Could not obtain effective sshd configuration: ${error_text:-unknown error}"
  fi
  source_description="local sshd -T"
fi

get_value() {
  local key=$1
  awk -v wanted="$key" '$1 == wanted {$1=""; sub(/^[[:space:]]+/, ""); print; exit}' "$effective_file"
}

record() {
  local status=$1 setting=$2 value=$3 reason=$4
  printf '%s\t%s\t%s\t%s\n' "$status" "$setting" "$value" "$reason" >>"$findings_file"
}

check_equals() {
  local setting=$1 expected=$2 fail_reason=$3
  local value
  value=$(get_value "$setting")
  if [[ -z $value ]]; then
    record WARN "$setting" "(missing)" "Setting was not present in the supplied effective config."
  elif [[ $value == "$expected" ]]; then
    record PASS "$setting" "$value" "Matches the hardened value."
  else
    record FAIL "$setting" "$value" "$fail_reason"
  fi
}

weak_items() {
  local csv=$1 expression=$2
  tr ',' '\n' <<< "$csv" | awk -v pattern="$expression" 'tolower($0) ~ pattern {print}' | paste -sd, -
}

: >"$findings_file"

check_equals passwordauthentication no "Password authentication increases exposure to guessing and credential reuse."
check_equals kbdinteractiveauthentication no "Keyboard-interactive authentication can permit password-like challenges."
check_equals permitemptypasswords no "Empty-password logins must remain disabled."

root_login=$(get_value permitrootlogin)
case "$root_login" in
  no) record PASS permitrootlogin "$root_login" "Direct root login is disabled." ;;
  prohibit-password|without-password)
    record WARN permitrootlogin "$root_login" "Root key login remains possible; confirm this is required and tightly controlled."
    ;;
  "") record WARN permitrootlogin "(missing)" "Setting was not present in the supplied effective config." ;;
  *) record FAIL permitrootlogin "$root_login" "Direct root login is broadly enabled." ;;
esac

check_equals x11forwarding no "X11 forwarding expands SSH session capabilities and attack surface."

tcp_forward=$(get_value allowtcpforwarding)
case "$tcp_forward" in
  no) record PASS allowtcpforwarding "$tcp_forward" "TCP forwarding is disabled." ;;
  "") record WARN allowtcpforwarding "(missing)" "Setting was not present in the supplied effective config." ;;
  *) record WARN allowtcpforwarding "$tcp_forward" "Forwarding is enabled; verify it is required for this server role." ;;
esac

max_auth=$(get_value maxauthtries)
if [[ $max_auth =~ ^[0-9]+$ ]] && (( max_auth <= 4 )); then
  record PASS maxauthtries "$max_auth" "Authentication attempts are limited."
elif [[ -z $max_auth ]]; then
  record WARN maxauthtries "(missing)" "Setting was not present in the supplied effective config."
else
  record WARN maxauthtries "$max_auth" "Consider limiting MaxAuthTries to 4 or fewer."
fi

log_level=$(get_value loglevel)
case "$log_level" in
  VERBOSE|verbose) record PASS loglevel "$log_level" "Verbose authentication logging is enabled." ;;
  INFO|info) record WARN loglevel "$log_level" "INFO is usable; VERBOSE adds key fingerprints for investigations." ;;
  "") record WARN loglevel "(missing)" "Setting was not present in the supplied effective config." ;;
  *) record WARN loglevel "$log_level" "Confirm the log level provides adequate authentication visibility." ;;
esac

ciphers=$(get_value ciphers)
weak_ciphers=$(weak_items "$ciphers" '^(3des-cbc|aes[0-9]+-cbc|arcfour.*|blowfish-cbc|cast128-cbc)$')
if [[ -z $ciphers ]]; then
  record WARN ciphers "(missing)" "Cipher list was not present in the supplied effective config."
elif [[ -n $weak_ciphers ]]; then
  record FAIL ciphers "$weak_ciphers" "Legacy CBC, RC4, or small-block ciphers are enabled."
else
  record PASS ciphers "$ciphers" "No configured legacy cipher matched the audit list."
fi

macs=$(get_value macs)
weak_macs=$(weak_items "$macs" '^(hmac-md5.*|hmac-sha1|hmac-sha1-96|umac-64.*)$')
if [[ -z $macs ]]; then
  record WARN macs "(missing)" "MAC list was not present in the supplied effective config."
elif [[ -n $weak_macs ]]; then
  record FAIL macs "$weak_macs" "Legacy MD5, SHA-1, or 64-bit MACs are enabled."
else
  record PASS macs "$macs" "No configured legacy MAC matched the audit list."
fi

kex=$(get_value kexalgorithms)
weak_kex=$(weak_items "$kex" '^(diffie-hellman-group1-sha1|diffie-hellman-group14-sha1|diffie-hellman-group-exchange-sha1)$')
if [[ -z $kex ]]; then
  record WARN kexalgorithms "(missing)" "Key-exchange list was not present in the supplied effective config."
elif [[ -n $weak_kex ]]; then
  record FAIL kexalgorithms "$weak_kex" "SHA-1-based legacy key exchange is enabled."
else
  record PASS kexalgorithms "$kex" "No configured legacy key exchange matched the audit list."
fi

hostkey_algorithms=$(get_value hostkeyalgorithms)
weak_hostkeys=$(weak_items "$hostkey_algorithms" '^(ssh-dss|ssh-rsa)$')
if [[ -z $hostkey_algorithms ]]; then
  record WARN hostkeyalgorithms "(missing)" "Host-key algorithm list was not present in the supplied effective config."
elif [[ -n $weak_hostkeys ]]; then
  record FAIL hostkeyalgorithms "$weak_hostkeys" "Legacy DSA or SHA-1 RSA host-key signatures are enabled."
else
  record PASS hostkeyalgorithms "$hostkey_algorithms" "No configured legacy host-key algorithm matched the audit list."
fi

pass_count=$(awk -F '\t' '$1 == "PASS" {count++} END {print count + 0}' "$findings_file")
warn_count=$(awk -F '\t' '$1 == "WARN" {count++} END {print count + 0}' "$findings_file")
fail_count=$(awk -F '\t' '$1 == "FAIL" {count++} END {print count + 0}' "$findings_file")

{
  printf 'OpenSSH Server Security Audit\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Source: %s\n\n' "$source_description"
  printf 'Summary: PASS=%s WARN=%s FAIL=%s\n\n' "$pass_count" "$warn_count" "$fail_count"

  while IFS=$'\t' read -r status setting value reason; do
    printf '[%s] %s\n' "$status" "$setting"
    printf '  Value: %s\n' "$value"
    printf '  Note: %s\n\n' "$reason"
  done <"$findings_file"

  printf 'Review guidance\n'
  printf '%s\n' '- Test proposed changes with sshd -t before reloading the service.'
  printf '%s\n' '- Keep an existing administrative session open during SSH changes.'
  printf '%s\n' '- Account for Match blocks by running sshd -T with the relevant -C context.'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report_file" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report_file"
fi
