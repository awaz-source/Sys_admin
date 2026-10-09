#!/usr/bin/env bash
# Generate a timestamped Markdown checklist for a system maintenance window.
#
# Examples:
#   ./maintenance_checklist.sh -t "Patch web servers" -s web01,web02
#   ./maintenance_checklist.sh -t "Upgrade PostgreSQL" -s db01 -c CHG-1042 \
#     -w "2026-10-10 02:00-03:00 UTC" -o postgres-upgrade.md

set -uo pipefail
umask 077

title=""
servers=""
change_id="Not assigned"
window="Not specified"
output_file=""
force=0

usage() {
  cat <<'EOF'
Usage: maintenance_checklist.sh -t TITLE -s HOSTS [OPTIONS]

Create a reusable Markdown checklist for planning, executing, verifying, and
documenting a system maintenance change. HOSTS is a comma-separated list.

Required:
  -t TITLE   Short description of the maintenance work.
  -s HOSTS   Comma-separated target hosts or systems.

Options:
  -c ID      Change or ticket ID (default: Not assigned).
  -w WINDOW  Planned maintenance window (default: Not specified).
  -o FILE    Output path (default: maintenance-YYYYmmdd-HHMMSS.md).
  -F         Overwrite the output file if it already exists.
  -h         Show this help.

The generated checklist contains no credentials and is created with mode 600.
EOF
}

die() {
  printf 'Error: %s\n' "$*" >&2
  exit 2
}

while getopts ':t:s:c:w:o:Fh' option; do
  case "$option" in
    t) title=$OPTARG ;;
    s) servers=$OPTARG ;;
    c) change_id=$OPTARG ;;
    w) window=$OPTARG ;;
    o) output_file=$OPTARG ;;
    F) force=1 ;;
    h) usage; exit 0 ;;
    :) die "Option -$OPTARG requires an argument." ;;
    \?) die "Unknown option: -$OPTARG" ;;
  esac
done
shift $((OPTIND - 1))

(( $# == 0 )) || die "Unexpected argument: $1"
[[ -n ${title//[[:space:]]/} ]] || die "TITLE is required."
[[ -n ${servers//[[:space:],]/} ]] || die "At least one target host is required."
if [[ $servers =~ ^[[:space:]]*, || $servers =~ ,[[:space:]]*$ || $servers =~ ,[[:space:]]*, ]]; then
  die "HOSTS contains an empty entry."
fi

if [[ -z $output_file ]]; then
  output_file="maintenance-$(date +%Y%m%d-%H%M%S).md"
fi
[[ ! -e $output_file || $force -eq 1 ]] || die "Output already exists; use -F to overwrite: $output_file"

output_dir=$(dirname -- "$output_file")
[[ -d $output_dir ]] || die "Output directory does not exist: $output_dir"

tmp_file=$(mktemp "${TMPDIR:-/tmp}/maintenance-checklist.XXXXXX") || die "Could not create temporary file."
trap 'find "$tmp_file" -type f -delete 2>/dev/null' EXIT HUP INT TERM

host_rows=""
IFS=',' read -r -a host_list <<< "$servers"
for host in "${host_list[@]}"; do
  host=${host#"${host%%[![:space:]]*}"}
  host=${host%"${host##*[![:space:]]}"}
  [[ -n $host ]] || die "HOSTS contains an empty entry."
  host_rows+="- [ ] \`$host\` verified before change"$'\n'
done

generated=$(date --iso-8601=seconds 2>/dev/null || date)
cat >"$tmp_file" <<EOF
# Maintenance Checklist: $title

- **Change ID:** $change_id
- **Window:** $window
- **Generated:** $generated
- **Coordinator:** _TBD_
- **Rollback owner:** _TBD_

## Scope

$host_rows
## Pre-change

- [ ] Confirm approvals and stakeholder notification
- [ ] Record the current application and service health
- [ ] Confirm a recent backup or snapshot and test restore access
- [ ] Confirm monitoring access and define success criteria
- [ ] Document the rollback trigger, commands, and estimated duration
- [ ] Verify console or out-of-band access

## Execution

- [ ] Announce the maintenance start
- [ ] Record the starting configuration or package versions
- [ ] Apply the approved change one target at a time
- [ ] Check service status and logs after each target
- [ ] Record deviations, commands, and timestamps below

### Execution notes

| Time | Target | Action | Result |
|---|---|---|---|
| | | | |

## Verification

- [ ] All expected services are active
- [ ] Application smoke test passed
- [ ] No new high-severity log events appeared
- [ ] Resource usage is within the normal range
- [ ] Monitoring and alerting are healthy
- [ ] Stakeholder validation completed

## Rollback (if required)

- [ ] Stop further deployment
- [ ] Capture evidence needed for troubleshooting
- [ ] Restore the previous known-good state
- [ ] Verify services, logs, monitoring, and user access
- [ ] Notify stakeholders of rollback status

## Closeout

- [ ] Record final versions and configuration state
- [ ] Attach relevant logs, screenshots, or monitoring links
- [ ] Update the change record with results
- [ ] Announce completion and schedule follow-up actions

**Outcome:** _Successful / Rolled back / Partially completed_

**Follow-up actions:**

- [ ] _None recorded_
EOF

install -m 600 -- "$tmp_file" "$output_file" || die "Could not write output: $output_file"
printf 'Checklist saved to %s\n' "$output_file"
