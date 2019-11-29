#!/bin/bash

# reprocess_bounces.sh V1.0.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

# return codes:
# 0 - skipped
# 1 - reprocessed
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

# get header field by label
# parameters:
# $1 - email file
# $2 - header label
# return values:
# header field
get_header() {
    HEADER_START="$(grep -i -n "^$2:" "$1" | head -1 | cut -f1 -d\:)"

    [ -z "$HEADER_START" ] && return 1

    HEADER_END="$(expr $HEADER_START + $(sed -n "$(expr $HEADER_START + 1),\$ p" "$1" | grep -n '^\S' | head -1 | cut -f1 -d\:) - 1)"

    [ -z "$HEADER_END" ] && return 1

    echo $(sed -n "$HEADER_START,$HEADER_END p" "$1") | awk 'match($0, /^[^ ]+: *(.*)/, a) {print a[1]}'
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

SUBJECT="$(get_header "$1" 'subject')"

if ! echo "$SUBJECT" | grep -q 'Undelivered Mail Returned to Sender'; then
    SENDER="$(get_header "$1" 'return-path' | awk 'match($0, /<([^]]+)>/, a) {print a[1]}')"
    RECIPIENT="$(get_header "$1" 'received' | awk 'match($0, /from.*by.*for <([^]]+)>;/, a) {print a[1]}')"

    if [ -z "$RECIPIENT" ]; then
        echo 'Cannot determine recipient'
        exit 99
    fi

    /usr/sbin/sendmail.postfix -f "$SENDER" "$RECIPIENT" < "$1"

    exit 1
fi

exit 0
