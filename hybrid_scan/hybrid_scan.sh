#!/bin/bash

# hybrid_scan.sh V1.0.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

# return codes:
# 0 - benign
# 1 - malware
# 99 - unrecoverable error

CMD_VXAPI="/opt/cs-gateway/scripts/netcon/VxAPI/vxapi.py"
TYPE_WINDOWS=120
TYPE_LINUX=300

LOG_PREFIX='>>>>'
LOG_SUFFIX='<<<<'

TIME_QUICK=30 # in seconds
TIME_FULL=60 # in seconds

# writes message to log file with the defined log pre-/suffix 
# parameters:
# $1 - message
# return values:
# none
write_log() {
    echo "$LOG_PREFIX$1$LOG_SUFFIX" >> "$FILE_LOG"
}

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $(basename $0) file_to_scan log_file"
    exit 99
fi

FILE_LOG="$2"

if ! [ -f "$1" ]; then
    write_log "Cannot open file '$1'"
    exit 99
fi

SCAN_ID="$($CMD_VXAPI scan_file -nstp 1 -aca 0 $1 all | grep '^\s*"id": ' | head -1 | awk -F [\"\"] '{print $4}')"

if [ -z "$SCAN_ID" ]; then
    write_log 'Cannot determine scan ID'
    exit 99
fi

while true; do
    sleep $TIME_QUICK
    SCAN_RESULT="$($CMD_VXAPI scan_get_result $SCAN_ID)"
    SCAN_FINISHED="$(echo $SCAN_RESULT | awk 'match($0, /"finished": ([^,]+),/, a) {print a[1]}')"
    if [ "$SCAN_FINISHED" = 'true' ]; then
        break
    elif [ -z "$SCAN_FINISHED" ]; then
        write_log 'Cannot determine scan status'
        exit 99
    fi
done

SCAN_HASH="$(echo $SCAN_RESULT | awk 'match($0, /"sha256": "([^"]+)",/, a) {print a[1]}')"

if [ -z "$SCAN_HASH" ]; then
    write_log 'Cannot determine scan hash'
    exit 99
fi

SCAN_OVERVIEW="$($CMD_VXAPI overview_get $SCAN_HASH)"

SCAN_ARCH="$(echo $SCAN_OVERVIEW | awk 'match($0, /"architecture": "([^"]+)"/, a) {print a[1]}')"
[ -z "$SCAN_ARCH" ] && SCAN_ARCH="$(echo $SCAN_OVERVIEW | awk 'match($0, /"type_short": \[ "([^"]+)"/, a) {print a[1]}')"

if [ -z "$SCAN_ARCH" ]; then
    write_log 'Cannot determine file architecture'
    exit 99
fi

case "$SCAN_ARCH" in
    'WINDOWS' | 'peexe')
        SCAN_TYPE="$TYPE_WINDOWS";;
    'LINUX' | 'elf')
        SCAN_TYPE="$TYPE_LINUX";;
    *)
        write_log "Unsupported file architecture '$SCAN_ARCH'"
        exit 99;;
esac

SCAN_ID="$($CMD_VXAPI scan_convert_to_full -nstp 1 -aca 0 $SCAN_ID $SCAN_TYPE | grep '^\s*"job_id": ' | awk -F [\"\"] '{print $4}')"

if [ -z "$SCAN_ID" ]; then
    write_log 'Cannot determine sandbox scan ID'
    exit 99
fi

while true; do
    sleep $TIME_FULL
    SCAN_FINISHED="$($CMD_VXAPI report_get_state $SCAN_ID | grep '^\s*"state": ' | awk -F [\"\"] '{print $4}')"

    if [ "$SCAN_FINISHED" = 'SUCCESS' ]; then
        break
    elif [ "$SCAN_FINISHED" = 'ERROR' ]; then
        write_log 'Error in sandbox scan'
        exit 99
    elif [ -z "$SCAN_FINISHED" ]; then
        write_log 'Cannot determine sandbox scan result'
        exit 99
    fi
done

SCAN_RESULT="$($CMD_VXAPI report_get_summary $SCAN_ID)"

if [ -z "$SCAN_RESULT" ]; then
    write_log 'Cannot determine scan result'
    exit 99
fi

SCAN_VERDICT="$(echo $SCAN_RESULT | awk 'match($0, /"verdict": "([^"]+)",/, a) {print a[1]}')"

if [ -z "$SCAN_VERDICT" ]; then
    echo 'Cannot determine scan verdict'
    write_log 99
fi

case "$SCAN_VERDICT" in
    'no verdict' | 'whitelisted')
        write_log 'Benign'
        exit 0;;
    'malicious')
        write_log 'Malware'
        exit 1;;
    *)
        write_log "Undefined verdict '$SCAN_VERDICT'"
        exit 99;;
esac
