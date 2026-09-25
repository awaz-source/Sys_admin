#!/usr/bin/env bash
# Keep timestamped system administration notes in daily Markdown files.
#
# Usage:
#   ./admin_notes.sh add "Restarted nginx after certificate renewal"
#   ./admin_notes.sh today
#   ./admin_notes.sh recent 7
#   ./admin_notes.sh search "nginx"
#
# Set ADMIN_NOTES_DIR to choose a storage directory. The default is:
#   ~/.local/share/sys-admin-notes

set -euo pipefail

notes_dir=${ADMIN_NOTES_DIR:-"${XDG_DATA_HOME:-$HOME/.local/share}/sys-admin-notes"}

usage() {
  sed -n '2,11p' "$0" | sed 's/^# \{0,1\}//'
}

prepare_notes_dir() {
  install -d -m 700 "$notes_dir"
}

daily_file() {
  printf '%s/%s.md\n' "$notes_dir" "$(date +%F)"
}

add_note() {
  if (( $# == 0 )); then
    printf 'Error: add requires note text.\n' >&2
    exit 2
  fi

  prepare_notes_dir
  local file
  file=$(daily_file)

  if [[ ! -e $file ]]; then
    {
      printf '# Administration Notes: %s\n\n' "$(date +%F)"
    } >"$file"
    chmod 600 "$file"
  fi

  printf -- '- %s — %s\n' "$(date +%T)" "$*" >>"$file"
  printf 'Note added to %s\n' "$file"
}

show_today() {
  local file
  file=$(daily_file)

  if [[ -f $file ]]; then
    cat "$file"
  else
    printf 'No administration notes recorded today.\n'
  fi
}

show_recent() {
  local days=${1:-7}
  if ! [[ $days =~ ^[1-9][0-9]*$ ]]; then
    printf 'Error: recent DAYS must be a positive integer.\n' >&2
    exit 2
  fi

  if [[ ! -d $notes_dir ]]; then
    printf 'No administration notes found.\n'
    return
  fi

  local found=0
  while IFS= read -r -d '' file; do
    found=1
    cat "$file"
    printf '\n'
  done < <(
    find "$notes_dir" -maxdepth 1 -type f -name '*.md' -mtime "-$days" -print0 |
      sort -z
  )

  if (( found == 0 )); then
    printf 'No notes found from the last %s days.\n' "$days"
  fi
}

search_notes() {
  if (( $# == 0 )); then
    printf 'Error: search requires a text pattern.\n' >&2
    exit 2
  fi

  if [[ ! -d $notes_dir ]]; then
    printf 'No administration notes found.\n'
    return
  fi

  if command -v rg >/dev/null 2>&1; then
    rg --fixed-strings --ignore-case --glob '*.md' -- "$*" "$notes_dir" || true
  else
    grep -R -F -i --include='*.md' -- "$*" "$notes_dir" || true
  fi
}

case ${1:-} in
  add)
    shift
    add_note "$@"
    ;;
  today)
    show_today
    ;;
  recent)
    shift
    show_recent "${1:-7}"
    ;;
  search)
    shift
    search_notes "$@"
    ;;
  -h|--help|help)
    usage
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac
