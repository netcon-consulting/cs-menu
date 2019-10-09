#!/bin/bash

# check_dkim.sh V1.1.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

# return codes:
# 0 - valid DKIM signature
# 1 - no DKIM signature
# 2 - invalid DKIM signature

DKIM_LOG="/tmp/dkim-$(date +'%Y-%m').log"

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

# get header field by label
# parameters:
# $1 - email file
# $2 - header label
# return values:
# header field
get_header() {
    HEADER_START="$(grep -n "^$2" "$1" | head -1 | cut -f1 -d\:)"

    if [ -z "$HEADER_START" ]; then
        write_log 'Cannot find start of header line'
        exit 99
    fi

    HEADER_END="$(expr $HEADER_START + $(sed -n "$(expr $HEADER_START + 1),\$ p" "$1" | grep -n '^\S' | head -1 | cut -f1 -d\:) - 1)"

    if [ -z "$HEADER_END" ]; then
        write_log 'Cannot find end of header line'
        exit 99
    fi

    echo $(sed -n "$HEADER_START,$HEADER_END p" "$1") | awk "match(\$0, /$2: ?(.*)/, a) {print a[1]}"
}

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $(basename $0) email_file log_file"
    exit 99
fi

FILE_LOG="$2"

if ! [ -f "$1" ]; then
    write_log "Cannot open file '$1'"
    exit 99
fi

HEADER_FROM="$(get_header "$1" 'From')"

if [ -z "$HEADER_FROM" ]; then
    write_log 'From header is empty'
    exit 99
fi

HEADER_TO="$(get_header "$1" 'To')"

if [ -z "$HEADER_TO" ]; then
    write_log 'To header is empty'
    exit 99
fi

HEADER_SUBJECT="$(get_header "$1" 'Subject')"

if [ -z "$HEADER_SUBJECT" ]; then
    write_log 'Subject header is empty'
    exit 99
fi

HEADER_DKIM="$(get_header "$1" 'x-msw-original-dkim-signature')"

if ! [ -z "$HEADER_DKIM" ]; then
    echo "[$(date +'%F %T')] from=$HEADER_FROM, to=$HEADER_TO, subject=$HEADER_SUBJECT, dkim_domain=$(echo "$HEADER_DKIM" | awk 'match($0, /d=([^;]+);/, a) {print a[1]}'), dkim_selector=$(echo "$HEADER_DKIM" | awk 'match($0, /s=([^;]+);/, a) {print a[1]}')" >> "$DKIM_LOG"
fi
