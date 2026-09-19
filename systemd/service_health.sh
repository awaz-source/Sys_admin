#!/usr/bin/env bash
# Check systemd services and show recent logs for unhealthy units.
# Usage: bash systemd/service_health.sh sshd nginx

set -u

if (( $# == 0 )); then
  printf 'Usage: %s SERVICE [SERVICE ...]\n' "${0##*/}" >&2
  exit 2
fi

if ! command -v systemctl >/dev/null 2>&1 || ! command -v journalctl >/dev/null 2>&1; then
  printf 'Error: systemctl and journalctl are required.\n' >&2
  exit 2
fi

failed=0
for input in "$@"; do
  unit="$input"
  [[ "$unit" == *.* ]] || unit="$unit.service"

  load_state=$(systemctl show --property=LoadState --value "$unit" 2>/dev/null)
  if [[ "$load_state" != "loaded" ]]; then
    printf '[UNKNOWN] %s (load state: %s)\n' "$unit" "${load_state:-unavailable}"
    failed=1
    continue
  fi

  state=$(systemctl is-active "$unit" 2>/dev/null) || :
  if [[ "$state" == "active" ]]; then
    printf '[OK] %s is active\n' "$unit"
    continue
  fi

  printf '[ALERT] %s is %s\n' "$unit" "${state:-unknown}"
  systemctl status "$unit" --no-pager --lines=0 2>&1 || :
  journalctl --unit="$unit" --lines=10 --no-pager 2>&1 || :
  failed=1
done

exit "$failed"
