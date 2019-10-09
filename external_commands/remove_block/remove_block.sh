#!/bin/bash

# remove_block.sh V1.0.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

# return codes:
# 0 - email not modified
# 1 - one or more blocks removed
# 99 - unrecoverable error

# list of blocks defined by the first and last line (separated by comma)
LIST_BLOCK='Sicherheitspr,Signatur: '
LIST_BLOCK+=$'\n''<table class=3D"MsoNormalTable" border=3D"0" cellspacing=3D"0" cellpadding=,</table>'

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

remove_block() {
    BLOCK_START="$(grep -n "^$2" "$1" | head -1 | cut -f1 -d\:)"

    if ! [ -z "$BLOCK_START" ]; then
        BLOCK_END="$(expr $BLOCK_START + $(sed -n "$(expr $BLOCK_START + 1),\$ p" "$1" | grep -n "^$3" | head -1 | cut -f1 -d\:))"

        if ! [ -z "$BLOCK_END" ]; then
            sed -i "$BLOCK_START,$BLOCK_END d" "$1"

            return 1
        fi
    fi
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

MODIFIED=''

while read BLOCK; do
    remove_block "$1" "$(echo "$BLOCK" | awk -F, '{print $1}')" "$(echo "$BLOCK" | awk -F, '{print $2}')" || MODIFIED=1
done < <(echo "$LIST_BLOCK")

[ "$MODIFIED" = 1 ] && exit 1 || exit 0
