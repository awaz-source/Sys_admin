#!/usr/bin/env bash
# Audit an nftables input chain for common defensive policy gaps.
# Authorized defensive use only. This script is read-only and never changes rules.
#
# Examples:
#   sudo ./nftables_input_security_audit.sh
#   ./nftables_input_security_audit.sh -f saved-ruleset.nft
#   sudo ./nftables_input_security_audit.sh -o nftables-audit.txt
#
# Exit codes: 0 no configured gaps found, 1 findings require review, 2 collection error.

set -uo pipefail
umask 077

ruleset_file=""
output=""

usage() {
  cat <<'USAGE'
Usage: nftables_input_security_audit.sh [-f RULESET] [-o REPORT]

Options:
  -f FILE    Audit an exported nftables ruleset instead of the live host
  -o REPORT  Save the report with permissions set to 600
  -h         Show this help

Without -f, the script runs `nft list ruleset`. It inspects base chains with an
input hook for a default-deny policy, established/related state handling,
loopback acceptance, unconditional accept rules, and unrestricted SSH, RDP, or
VNC ports. Findings are heuristic; validate intended exposure and upstream
controls before changing production firewall policy.
USAGE
}

while getopts ":f:o:h" option; do
  case "$option" in
    f) ruleset_file=$OPTARG ;;
    o) output=$OPTARG ;;
    h) usage; exit 0 ;;
    :) printf 'Option -%s requires an argument.\n' "$OPTARG" >&2; exit 2 ;;
    \?) printf 'Unknown option: -%s\n' "$OPTARG" >&2; usage >&2; exit 2 ;;
  esac
done

tmp_ruleset=$(mktemp)
tmp_input=$(mktemp)
tmp_findings=$(mktemp)
tmp_report=$(mktemp)
trap 'rm -f "$tmp_ruleset" "$tmp_input" "$tmp_findings" "$tmp_report"' EXIT

if [[ -n $ruleset_file ]]; then
  if [[ ! -f $ruleset_file || ! -r $ruleset_file ]]; then
    printf 'Ruleset is not a readable regular file: %s\n' "$ruleset_file" >&2
    exit 2
  fi
  cp -- "$ruleset_file" "$tmp_ruleset" || exit 2
  source_label=$ruleset_file
else
  command -v nft >/dev/null 2>&1 || {
    printf 'nft was not found; use -f with an exported ruleset.\n' >&2
    exit 2
  }
  if ! nft list ruleset >"$tmp_ruleset" 2>/dev/null; then
    printf 'Unable to read the live nftables ruleset; elevated privileges may be required.\n' >&2
    exit 2
  fi
  source_label='live nft list ruleset'
fi

# Extract complete chain blocks, retaining only base chains that contain hook input.
awk '
  function brace_delta(text, opens, closes) {
    opens = gsub(/\{/, "{", text)
    closes = gsub(/\}/, "}", text)
    return opens - closes
  }
  /^[[:space:]]*chain[[:space:]]+[^[:space:]]+[[:space:]]*\{/ {
    capturing = 1
    block = $0
    depth = brace_delta($0)
    if (depth == 0) {
      if (block ~ /hook[[:space:]]+input([[:space:]]|;)/) print block
      capturing = 0
    }
    next
  }
  capturing {
    block = block "\n" $0
    depth += brace_delta($0)
    if (depth == 0) {
      if (block ~ /hook[[:space:]]+input([[:space:]]|;)/) print block
      capturing = 0
    }
  }
' "$tmp_ruleset" >"$tmp_input"

input_chain_count=$(grep -Ec '^[[:space:]]*chain[[:space:]]+' "$tmp_input" || true)
finding_count=0

add_finding() {
  local severity=$1 location=$2 reason=$3
  printf '%s\t%s\t%s\n' "$severity" "$location" "$reason" >>"$tmp_findings"
  finding_count=$((finding_count + 1))
}

if (( input_chain_count == 0 )); then
  add_finding HIGH ruleset 'no nftables base chain with hook input was found'
else
  if ! grep -Eqi 'hook[[:space:]]+input[^;]*;[^#]*(policy[[:space:]]+(drop|reject))' "$tmp_input"; then
    add_finding HIGH input-chain 'no default drop/reject policy was identified'
  fi

  if ! grep -Eqi 'ct[[:space:]]+state[[:space:]]+([^#;]*,)?[[:space:]]*(established|related)([^#;]*,)?[^#;]*(established|related)?[^#;]*accept' "$tmp_input"; then
    add_finding MEDIUM input-chain 'no established/related connection accept rule was identified'
  fi

  if ! grep -Eqi 'iif(name)?[[:space:]]+("lo"|lo)[^#;]*accept' "$tmp_input"; then
    add_finding MEDIUM input-chain 'no loopback interface accept rule was identified'
  fi

  while IFS=: read -r line_number rule; do
    [[ -n $line_number ]] || continue
    add_finding HIGH "input-chain:$line_number" 'unconditional accept rule permits all matching input traffic'
  done < <(grep -En '^[[:space:]]*(counter[[:space:]]+)?accept([[:space:]]*(comment[[:space:]]+"[^"]*")?[[:space:]]*)?$' "$tmp_input" || true)

  while IFS=: read -r line_number rule; do
    [[ -n $line_number ]] || continue
    if ! grep -Eqi '(ip|ip6)[[:space:]]+saddr|@[[:alnum:]_-]+' <<<"$rule"; then
      port=$(grep -Eo '(22|3389|5900)' <<<"$rule" | head -n 1)
      add_finding MEDIUM "input-chain:$line_number" "administrative port ${port:-unknown} is accepted without a source restriction on the same rule"
    fi
  done < <(grep -En '(tcp|udp)[[:space:]].*dport([^#;])*(22|3389|5900)([^#;])*accept' "$tmp_input" || true)
fi

{
  printf 'nftables Input Security Audit\n'
  printf 'Generated (UTC): %s\n' "$(date -u '+%Y-%m-%dT%H:%M:%SZ')"
  printf 'Host: %s\n' "$(hostname 2>/dev/null || printf unknown)"
  printf 'Ruleset source: %s\n' "$source_label"
  printf 'Input base chains inspected: %d\n' "$input_chain_count"
  printf 'Review findings: %d\n' "$finding_count"

  printf '\n== Input chain policy ==\n'
  if (( input_chain_count == 0 )); then
    printf 'No input base chain was available to display.\n'
  else
    cat "$tmp_input"
  fi

  printf '\n== Findings requiring review ==\n'
  if (( finding_count == 0 )); then
    printf 'No configured input-policy gaps were identified by these checks.\n'
  else
    printf 'SEVERITY | LOCATION | REASON\n'
    sort -t $'\t' -k1,1 -k2,2 "$tmp_findings" | tr '\t' '|'
  fi

  printf '\n== Validation guidance ==\n'
  printf 'Confirm intended services, management networks, IPv4/IPv6 coverage, and upstream controls.\n'
  printf 'Test proposed changes from an approved console to avoid locking out remote administration.\n'
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
