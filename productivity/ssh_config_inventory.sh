#!/usr/bin/env bash
# Build a searchable inventory from explicit Host entries in an SSH config.
# The script reads configuration only; it never initiates network connections.
#
# Examples:
#   ./ssh_config_inventory.sh
#   ./ssh_config_inventory.sh -c ./team_ssh_config -o ssh-inventory.txt
#   ./ssh_config_inventory.sh -w -c ~/.ssh/config

set -uo pipefail
umask 077

config_file="${HOME}/.ssh/config"
output_file=""
include_patterns=0

usage() {
  cat <<'EOF'
Usage: ssh_config_inventory.sh [-c CONFIG] [-o REPORT] [-w]

Summarize SSH Host aliases, destinations, users, ports, identity files, and
ProxyJump values. The tool does not connect to any host or read private keys.

Options:
  -c FILE   SSH configuration file (default: ~/.ssh/config).
  -o FILE   Save the report with mode 600 instead of printing it.
  -w        Include wildcard/negated Host patterns (skipped by default).
  -h        Show this help.

Notes:
  - Include directives are reported but are not expanded automatically.
  - Values inherited from Host * blocks are not merged into later entries.
  - Run ssh -G ALIAS to inspect OpenSSH's fully resolved configuration.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':c:o:wh' option; do
  case "$option" in
    c) config_file=$OPTARG ;;
    o) output_file=$OPTARG ;;
    w) include_patterns=1 ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die "Unexpected argument: $1"
[[ -f $config_file ]] || die "SSH config is not a regular file: $config_file"
[[ -r $config_file ]] || die "SSH config is not readable: $config_file"
command -v awk >/dev/null 2>&1 || die "Required command not found: awk"

work_dir=$(mktemp -d "${TMPDIR:-/tmp}/ssh-config-inventory.XXXXXX") || die "Could not create temporary directory."
inventory_file="$work_dir/inventory.tsv"
includes_file="$work_dir/includes.txt"
report_file="$work_dir/report.txt"
trap 'find "$work_dir" -type f -delete 2>/dev/null; rmdir "$work_dir" 2>/dev/null' EXIT HUP INT TERM

awk -v include_patterns="$include_patterns" -v includes_file="$includes_file" '
  function reset_block() {
    hosts=""; hostname=""; user=""; port=""; identity=""; proxyjump=""
  }
  function value_after_keyword(line) {
    sub(/^[[:space:]]*[^[:space:]]+[[:space:]]+/, "", line)
    sub(/[[:space:]]+#.*$/, "", line)
    return line
  }
  function flush(aliases, count, i, alias, patterned) {
    if (hosts == "") return
    count=split(hosts, aliases, /[[:space:]]+/)
    for (i=1; i<=count; i++) {
      alias=aliases[i]
      if (alias == "") continue
      patterned=(alias ~ /[*?!]/)
      if (patterned && !include_patterns) { skipped++; continue }
      printf "%s\t%s\t%s\t%s\t%s\t%s\n", alias,
        (hostname != "" ? hostname : alias),
        (user != "" ? user : "(default)"),
        (port != "" ? port : "22"),
        (identity != "" ? identity : "(default)"),
        (proxyjump != "" ? proxyjump : "-")
    }
  }
  BEGIN { reset_block() }
  {
    line=$0
    sub(/^[[:space:]]+/, "", line)
    if (line == "" || line ~ /^#/) next
    split(line, fields, /[[:space:]]+/)
    key=tolower(fields[1])
    if (key == "host") {
      flush()
      reset_block()
      hosts=value_after_keyword(line)
    } else if (key == "include") {
      print value_after_keyword(line) >> includes_file
    } else if (hosts != "") {
      value=value_after_keyword(line)
      if (key == "hostname" && hostname == "") hostname=value
      else if (key == "user" && user == "") user=value
      else if (key == "port" && port == "") port=value
      else if (key == "identityfile" && identity == "") identity=value
      else if (key == "proxyjump" && proxyjump == "") proxyjump=value
    }
  }
  END {
    flush()
    printf "%d\n", skipped > (includes_file ".skipped")
  }
' "$config_file" >"$inventory_file"

entry_count=$(wc -l <"$inventory_file")
skipped_count=$(cat "$includes_file.skipped")
include_count=0
[[ -f $includes_file ]] && include_count=$(wc -l <"$includes_file")
duplicates=$(cut -f1 "$inventory_file" | sort | uniq -d)

{
  printf 'SSH Configuration Inventory\n'
  printf 'Generated: %s\n' "$(date --iso-8601=seconds 2>/dev/null || date)"
  printf 'Config: %s\n\n' "$(realpath -- "$config_file" 2>/dev/null || printf '%s' "$config_file")"
  printf 'Explicit aliases inventoried: %s\n' "$entry_count"
  printf 'Wildcard/negated patterns skipped: %s\n' "$skipped_count"
  printf 'Unexpanded Include directives: %s\n\n' "$include_count"

  printf '%-22s %-28s %-16s %-7s %-30s %s\n' \
    'ALIAS' 'HOSTNAME' 'USER' 'PORT' 'IDENTITY FILE' 'PROXYJUMP'
  printf '%-22s %-28s %-16s %-7s %-30s %s\n' \
    '----------------------' '----------------------------' '----------------' '-------' '------------------------------' '---------'
  if [[ -s $inventory_file ]]; then
    while IFS=$'\t' read -r alias hostname user port identity proxyjump; do
      printf '%-22s %-28s %-16s %-7s %-30s %s\n' \
        "$alias" "$hostname" "$user" "$port" "$identity" "$proxyjump"
    done <"$inventory_file"
  else
    printf 'No explicit Host aliases found.\n'
  fi

  printf '\nDuplicate aliases\n'
  [[ -n $duplicates ]] && printf '%s\n' "$duplicates" || printf 'None found.\n'

  printf '\nInclude directives (not expanded)\n'
  if [[ -s $includes_file ]]; then
    sed 's/^/- /' "$includes_file"
  else
    printf 'None found.\n'
  fi

  printf '\nTip: validate a resolved entry with: ssh -G ALIAS\n'
} >"$report_file"

if [[ -n $output_file ]]; then
  install -m 600 -- "$report_file" "$output_file" || die "Could not write report: $output_file"
  printf 'Report saved to %s\n' "$output_file"
else
  cat "$report_file"
fi
