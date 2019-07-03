#!/bin/bash

# check_qr.sh V1.1.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

# return codes:
# 0 - picture does not contain QR code
# 1 - picture contains QR code
# 99 - unrecoverable error

LOG_PREFIX='>>>>'
LOG_SUFFIX='<<<<'

# writes message to log file with the defined log pre-/suffix 
# parameters:
# $1 - message
# return values:
# none
write_log() {
    echo "$LOG_PREFIX$1$LOG_SUFFIX" >> "$FILE_LOG"
}

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $(basename $0) encrypted_zip log_file"
    exit 99
fi

FILE_LOG="$2"

if ! [ -f "$1" ]; then
    write_log "Cannot open file '$1'"
    exit 99
fi

if ! which zbarimg &>/dev/null; then
    write_log "'zbarimg' needs to be installed"
    exit 99
fi

RESULT="$(zbarimg "$1" 2>/dev/null)"

if [ "$?" = 0 ]; then
    URL="$(echo "$RESULT" | grep 'QR-Code:' | awk -F 'QR-Code:' '{print $2}' | grep -E '(http|www)')"
    [ -z "$URL" ] && write_log 'no URL found' || write_log "$URL"
    exit 1
fi

exit 0
