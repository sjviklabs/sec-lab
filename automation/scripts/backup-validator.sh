#!/usr/bin/env bash
#
# backup-validator.sh -- Validate backup recency, size, and integrity.
#
# Checks that backup files exist in a target directory, are not older
# than a configurable threshold, and are not suspiciously small.
# Optionally verifies file integrity against a SHA-256 checksum file.
#
# Usage:
#   bash backup-validator.sh <backup_dir> [max_age_hours]
#
# Examples:
#   bash backup-validator.sh /backup/daily/
#   bash backup-validator.sh /backup/daily/ 48
#   bash backup-validator.sh /backup/weekly/ 168
#
# Exit codes:
#   0 -- All checks passed
#   1 -- One or more checks failed
#   2 -- Usage error
#

set -euo pipefail

DEFAULT_MAX_AGE_HOURS=24
MIN_FILE_SIZE_BYTES=1024
CHECKSUM_FILE="checksums.sha256"

if [[ -t 1 ]]; then
    RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
else
    RED=''; GREEN=''; YELLOW=''; NC=''
fi

pass()  { echo -e "  ${GREEN}[PASS]${NC} $*"; }
fail()  { echo -e "  ${RED}[FAIL]${NC} $*"; FAILURES=$((FAILURES + 1)); }
warn()  { echo -e "  ${YELLOW}[WARN]${NC} $*"; }
info()  { echo -e "  [INFO] $*"; }

usage() {
    echo "Usage: $0 <backup_directory> [max_age_hours]"
    echo "  backup_directory   Path to the directory containing backup files"
    echo "  max_age_hours      Maximum acceptable age in hours (default: ${DEFAULT_MAX_AGE_HOURS})"
    exit 2
}

if [[ $# -lt 1 ]]; then usage; fi

BACKUP_DIR="$1"
MAX_AGE_HOURS="${2:-$DEFAULT_MAX_AGE_HOURS}"
FAILURES=0

echo "============================================"
echo "  BACKUP VALIDATION REPORT"
echo "============================================"
echo ""
info "Backup directory: ${BACKUP_DIR}"
info "Max age threshold: ${MAX_AGE_HOURS} hours"
info "Min file size: ${MIN_FILE_SIZE_BYTES} bytes"
echo ""

echo "--- Directory Check ---"
if [[ -d "${BACKUP_DIR}" ]]; then
    pass "Backup directory exists"
else
    fail "Backup directory does not exist: ${BACKUP_DIR}"
    echo "Result: FAILED (${FAILURES} issue(s))"; exit 1
fi

echo ""
echo "--- File Presence Check ---"
FILE_COUNT=$(find "${BACKUP_DIR}" -maxdepth 1 -type f | wc -l)
if [[ "${FILE_COUNT}" -gt 0 ]]; then
    pass "Found ${FILE_COUNT} file(s) in backup directory"
else
    fail "Backup directory is empty"
    echo "Result: FAILED (${FAILURES} issue(s))"; exit 1
fi

echo ""
echo "--- File Age Check (max ${MAX_AGE_HOURS}h) ---"
MAX_AGE_SECONDS=$((MAX_AGE_HOURS * 3600))
NOW=$(date +%s)
while IFS= read -r -d '' file; do
    filename=$(basename "${file}")
    file_mtime=$(stat -c '%Y' "${file}" 2>/dev/null || stat -f '%m' "${file}" 2>/dev/null)
    age_seconds=$((NOW - file_mtime))
    age_hours=$((age_seconds / 3600))
    if [[ ${age_seconds} -gt ${MAX_AGE_SECONDS} ]]; then
        fail "${filename} is ${age_hours}h old (threshold: ${MAX_AGE_HOURS}h)"
    else
        pass "${filename} is ${age_hours}h old"
    fi
done < <(find "${BACKUP_DIR}" -maxdepth 1 -type f -print0)

echo ""
echo "--- File Size Check (min ${MIN_FILE_SIZE_BYTES} bytes) ---"
while IFS= read -r -d '' file; do
    filename=$(basename "${file}")
    file_size=$(stat -c '%s' "${file}" 2>/dev/null || stat -f '%z' "${file}" 2>/dev/null)
    if [[ ${file_size} -lt ${MIN_FILE_SIZE_BYTES} ]]; then
        fail "${filename} is ${file_size} bytes (suspiciously small)"
    else
        if [[ ${file_size} -ge 1073741824 ]]; then
            hr_size="$(echo "scale=1; ${file_size}/1073741824" | bc) GB"
        elif [[ ${file_size} -ge 1048576 ]]; then
            hr_size="$(echo "scale=1; ${file_size}/1048576" | bc) MB"
        elif [[ ${file_size} -ge 1024 ]]; then
            hr_size="$(echo "scale=1; ${file_size}/1024" | bc) KB"
        else
            hr_size="${file_size} bytes"
        fi
        pass "${filename} -- ${hr_size}"
    fi
done < <(find "${BACKUP_DIR}" -maxdepth 1 -type f -print0)

echo ""
echo "--- Integrity Check ---"
CHECKSUM_PATH="${BACKUP_DIR%/}/${CHECKSUM_FILE}"
if [[ -f "${CHECKSUM_PATH}" ]]; then
    info "Found checksum file: ${CHECKSUM_FILE}"
    pushd "${BACKUP_DIR}" > /dev/null
    if sha256sum --check --quiet "${CHECKSUM_FILE}" 2>/dev/null; then
        pass "All checksums verified"
    else
        fail "Checksum verification failed -- possible corruption"
    fi
    popd > /dev/null
else
    warn "No checksum file found (${CHECKSUM_FILE}) -- skipping integrity check"
fi

echo ""
echo "============================================"
if [[ ${FAILURES} -eq 0 ]]; then
    echo -e "  Result: ${GREEN}ALL CHECKS PASSED${NC}"
else
    echo -e "  Result: ${RED}FAILED -- ${FAILURES} issue(s) found${NC}"
fi
echo "============================================"
exit $( [[ ${FAILURES} -eq 0 ]] && echo 0 || echo 1 )