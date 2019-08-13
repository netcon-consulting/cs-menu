#!/bin/bash

# check_qr.sh V1.7.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

# return codes:
# 0 - picture does not contain QR code with non-whitelisted URL link with a domain listed at multi.surbl.org
# 1 - picture contains QR code with non-whitelisted URL link with a domain listed at multi.surbl.org
# 99 - unrecoverable error

LOG_PREFIX='>>>>'
LOG_SUFFIX='<<<<'

DIR_URL='/var/cs-gateway/uicfg/policy/urllists'
NAME_WHITELIST='Whitelist QR-Code'
NAME_BLACKLIST='Blacklist URL'
LIST_URLBL='surbl.org uribl.com'

# writes message to log file with the defined log pre-/suffix 
# parameters:
# $1 - message
# return values:
# none
write_log() {
    echo "$LOG_PREFIX$1$LOG_SUFFIX" >> "$FILE_LOG"
}

if [ -z "$1" ] || [ -z "$2" ]; then
    echo "Usage: $(basename $0) image_file log_file"
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

if [ "$?" = 0 ] && echo "$RESULT" | grep -q '^QR-Code:'; then
    LIST_URL="$(echo $RESULT | awk '{pattern="((https?://|www.)[^ ]+)"; while (match($0, pattern, arr)) {val = arr[1]; print val; sub(pattern, "")}}')"

    if ! [ -z "$LIST_URL" ]; then
        FILE_WHITE="$(grep -l "UrlList name=\"$NAME_WHITELIST\"" $DIR_URL/*.xml)"
        [ -z "$FILE_WHITE" ] || LIST_WHITE="$(xmlstarlet sel -t -m "UrlList/Url" -v . -n "$FILE_WHITE" | sed 's/^\*:\/\///')"

        for URL in $LIST_URL; do
            if [ -z "$LIST_WHITE" ] || ! echo "$LIST_WHITE" | grep -q "^$URL$"; then
                NAME_DOMAIN="$(echo "$URL" | awk 'match($0, /(https?:\/\/)?([^ \/]+)/, a) {print a[2]}')"

                FILE_BLACK="$(grep -l "UrlList name=\"$NAME_BLACKLIST\"" $DIR_URL/*.xml)"
                [ -z "$FILE_BLACK" ] || LIST_BLACK="$(xmlstarlet sel -t -m "UrlList/Url" -v . -n "$FILE_BLACK" | sed 's/^\*:\/\///')"
                if ! [ -z "$LIST_BLACK" ] && echo "$LIST_BLACK" | grep -q "^$URL$"; then
                    write_log "$URL"
                    exit 1
                fi

                for BLACKLIST in $LIST_URLBL; do
                    if ! [ -z "$(dig +short $NAME_DOMAIN.multi.$BLACKLIST)" ]; then
                        write_log "$URL"
                        exit 1
                    fi
                done
            fi
        done
    fi
fi

exit 0
