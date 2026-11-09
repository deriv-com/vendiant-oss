#!/usr/bin/env bash
set -euo pipefail

# Runs backup-script, verifies the latest dump was refreshed, then docker
# compose down, build, and up from the project root.

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
BACKUP_SCRIPT="${SCRIPT_DIR}/backup-script"
VENDIANT_SQL="${LATEST_BACKUP_PATH:-${PROJECT_ROOT}/Postgress/backups/database/latest.sql}"

mtime_seconds() {
  if [[ -f "$1" ]]; then
    stat -c '%Y' "$1"
  else
    echo 0
  fi
}

echo "Project root: ${PROJECT_ROOT}"

before_mtime="$(mtime_seconds "${VENDIANT_SQL}")"

if [[ ! -f "${BACKUP_SCRIPT}" ]]; then
  echo "ERROR: backup script not found at ${BACKUP_SCRIPT}" >&2
  exit 1
fi

echo "Running backup script..."
bash "${BACKUP_SCRIPT}"

after_mtime="$(mtime_seconds "${VENDIANT_SQL}")"

if [[ ! -f "${VENDIANT_SQL}" ]]; then
  echo "ERROR: ${VENDIANT_SQL} does not exist after backup." >&2
  exit 1
fi

if [[ "${after_mtime}" -le "${before_mtime}" ]]; then
  echo "ERROR: database dump was not newly updated (mtime before=${before_mtime}, after=${after_mtime})." >&2
  exit 1
fi

echo "Verified database dump updated (mtime ${before_mtime} -> ${after_mtime})."

cd "${PROJECT_ROOT}"

echo "docker compose build..."
docker compose build

echo "docker compose down..."
docker compose down

echo "docker compose up -d..."
docker compose up -d

echo "Done."
