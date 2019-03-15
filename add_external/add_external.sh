#!/bin/bash

# add_external.sh V1.1.1
#
# Copyright (c) 2018 NetCon Unternehmensberatung GmbH, info@netcon-consulting.com
#
# Authors: Uwe Sommer, Marc Dierksen

# return codes:
# 0 - not modified
# 5 - modified
# 99 - unrecoverable error

if [ -f "$1" ]; then
    # find start of first 'From: ' in email header
    FROM_START="$(grep -n '^\(F\|f\)rom: ' "$1" | head -1 | cut -f1 -d\:)"
    # find end of first 'From: ' in email header
    FROM_END="$(expr $FROM_START + $(sed -n "$(expr $FROM_START + 1),\$ p" "$1" | grep -n '^\S' | head -1 | cut -f1 -d\:) - 1)"
    # extract first 'From: ' line
    FROM_LINE="$(sed -n "$FROM_START,$FROM_END{p}" "$1")"
    if ! [ -z "$FROM_LINE" ]; then
        # extract 'From' keyword
        FROM_KEYWORD="$(echo $FROM_LINE | cut -c -5)"
        # extract sender
        FROM_SENDER="$(echo $FROM_LINE | cut -c 6-)"
        # skip if sender empty or already tagged
        if ! [ -z "$FROM_SENDER" ] && echo "$FROM_SENDER" | grep -q -v '"\[EXT\] '; then
            # try to find address in <>-brackets
            FROM_ADDRESS="$(echo $FROM_SENDER | awk 'match($0, /<(.+@.+\..+)>/, a) {print a[1]}')"
            # if address not in <>-brackets
            if [ -z "$FROM_ADDRESS" ]; then
                # try to find address
                FROM_ADDRESS="$(echo $FROM_SENDER | awk 'match($0, /(.+@.+\..+)/, a) {print a[1]}')"
                # if cannot find address then unrecoverable error (error code=99)
                [ -z "$FROM_ADDRESS" ] && exit 99
                # extract prefix and suffix before/after address
                FROM_PREFIX="$(echo $FROM_SENDER | awk -F "$FROM_ADDRESS" '{print $1}' | sed 's/^\s*//g' | sed 's/\s*$//g' | sed -E 's/\"(.*)\"/\1/')"
                FROM_SUFFIX="$(echo $FROM_SENDER | awk -F "$FROM_ADDRESS" '{print $2}' | sed 's/^\s*//g' | sed 's/\s*$//g')"
            else
                # extract prefix and suffix before/after address
                FROM_PREFIX="$(echo $FROM_SENDER | awk -F "<$FROM_ADDRESS>" '{print $1}' | sed 's/^\s*//g' | sed 's/\s*$//g' | sed -E 's/\"(.*)\"/\1/')"
                FROM_SUFFIX="$(echo $FROM_SENDER | awk -F "<$FROM_ADDRESS>" '{print $2}' | sed 's/^\s*//g' | sed 's/\s*$//g')"
            fi
            # construct new 'From: ' line from keyword, prefix (if not empty), 'EXT' tag, address and suffix (if not empty)
            FROM_NEW="$FROM_KEYWORD \"\[EXT\]"
            [ -z "$FROM_PREFIX" ] && FROM_NEW+=" $FROM_ADDRESS" || FROM_NEW+=" $FROM_PREFIX"
            FROM_NEW+="\" \<$FROM_ADDRESS\>"
            [ -z "$FROM_SUFFIX" ] || FROM_NEW+=" $FROM_SUFFIX"
            # delete old 'From: ' line in email header
            sed -i "$FROM_START,$FROM_END{d}" "$1"
            # add new 'From: ' line to email header
            sed -i "${FROM_START}i $FROM_NEW" "$1"
            exit 5
        fi
    fi
fi
exit 0
