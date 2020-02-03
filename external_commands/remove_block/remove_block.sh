#!/bin/bash

# remove_block.sh V1.1.0
#
# Copyright (c) 2019-2020 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

# return codes:
# 0 - email not modified
# 1 - one or more blocks removed
# 99 - unrecoverable error

# list of blocks defined by the first and last line (separated by comma)
LIST_BLOCK='\\** Externe Email **,--------------------------------'
LIST_BLOCK+=$'\n''<p class=\"MsoNormal\"><o:p>&nbsp;</o:p></p>,-------------------------------- <o:p></o:p></p>'

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
    declare HEADER_START HEADER_END

    HEADER_START="$(grep -i -n "^$2:" "$1" | head -1 | cut -f1 -d\:)"

    [ -z "$HEADER_START" ] && return 1

    HEADER_END="$(sed -n "$(expr "$HEADER_START" + 1),\$ p" "$1" | grep -n '^\S' | head -1 | cut -f1 -d\:)"

    [ -z "$HEADER_END" ] && return 1

    HEADER_END="$(expr "$HEADER_START" + "$HEADER_END" - 1)"

    echo $(sed -n "$HEADER_START,$HEADER_END p" "$1") | awk 'match($0, /^[^ ]+: *(.*)/, a) {print a[1]}'
}

remove_block() {
    declare BLOCK_START BLOCK_END

    BLOCK_START="$(echo "$1" | grep -n "^$2" | head -1 | cut -f1 -d\:)"

    if ! [ -z "$BLOCK_START" ]; then
        BLOCK_END="$(echo "$1" | sed -n "$(expr "$BLOCK_START" + 1),\$ p" | grep -n "^$3" | head -1 | cut -f1 -d\:)"

        if ! [ -z "$BLOCK_END" ]; then
            BLOCK_END="$(expr "$BLOCK_START" + "$BLOCK_END")"

            echo "$1" | sed "$BLOCK_START,$BLOCK_END d"

            return 1
        fi
    fi

    echo "$1"
}

clean_part() {
    declare MODIFIED PART_CLEANED BLOCK

    MODIFIED=''
    PART_CLEANED="$1"

    while read BLOCK; do
        PART_CLEANED="$(remove_block "$PART_CLEANED" "$(echo "$BLOCK" | awk -F, '{print $1}')" "$(echo "$BLOCK" | awk -F, '{print $2}')")"

        [ "$?" = 1 ] && MODIFIED=1
    done < <(echo "$LIST_BLOCK")

    echo "$PART_CLEANED"
    [ "$MODIFIED" = 1 ] && return 1
}

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $(basename "$0") email_file log_file"
    exit 99
fi

FILE_LOG="$2"

if ! [ -f "$1" ]; then
    write_log "Cannot open file '$1'"
    exit 99
fi

MODIFIED=''
CONTENT_TYPE="$(get_header "$1" 'content-type')"

if echo "$CONTENT_TYPE" | grep -q -i 'multipart/alternative'; then
    BOUNDARY="$(echo "$CONTENT_TYPE" | awk 'match($0, /boundary="([^"]+)"/, a) {print a[1]}')"

    if [ -z "$BOUNDARY" ]; then
        write_log 'Cannot find boundary'
        exit 99
    fi

    for NUM_BOUNDARY in 1 2; do
        LIST_BOUNDARY="$(grep -n "^\--$BOUNDARY\(--\)\?$" "$1" | cut -f1 -d\:)"

        INFO_START="$(expr "$(echo "$LIST_BOUNDARY" | sed -n "$NUM_BOUNDARY p")" + 1)"
        INFO_END="$(expr "$INFO_START" + "$(sed -n "$INFO_START,\$ p" "$1" | grep -n '^$' | head -1 | cut -f1 -d\:)" - 1)"

        CONTENT_INFO="$(sed -n "$INFO_START,$INFO_END p" "$1")"

        CONTENT_START="$(expr $INFO_END + 1)"
        CONTENT_END="$(expr "$(echo "$LIST_BOUNDARY" | sed -n "$(expr "$NUM_BOUNDARY" + 1) p")" - 2)"

        if echo "$CONTENT_INFO" | grep -q -i 'base64'; then
            CONTENT_NEW="$(clean_part "$(sed -n "$CONTENT_START,$CONTENT_END p" "$1" | base64 -d)")"

            RET_CODE="$?"

            CONTENT_NEW="$(echo "$CONTENT_NEW" | base64)"
        else
            CONTENT_NEW="$(clean_part "$(sed -n "$CONTENT_START,$CONTENT_END p" "$1")")"

            RET_CODE="$?"
        fi

        if [ "$RET_CODE" = 1 ]; then
            sed -i "$CONTENT_START,$CONTENT_END c$(echo "$CONTENT_NEW" | sed ':a;N;$!ba;s/\n/\\n/g')" "$1"

            MODIFIED=1
        fi
    done
else
    CONTENT_NEW="$(clean_part "$(cat "$1")")"

    if [ "$?" = 1 ]; then
        echo "$CONTENT_NEW" > "$1"

        MODIFIED=1
    fi
fi

[ "$MODIFIED" = 1 ] && exit 1 || exit 0
