#!/bin/bash

# check_sender_ip.sh V1.3.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, info@netcon-consulting.com
#
# Authors: Uwe Sommer, Marc Dierksen

# return codes:
# 0 - sender IP in list
# 5 - sender IP not in list
# 99 - unrecoverable error

IP_FILE='/tmp/TMPip_list'
IP_LINK='http://pxe.isdoll.de/ip_list'
MAX_AGE=21600 # in seconds
EMAIL_RECIPIENT='uwe@usommer.de'

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
    echo "Usage: $(basename $0) email_file log_file"
    exit 99
fi

FILE_LOG="$2"

# if email file does not exist then unrecoverable error
if ! [ -f "$1" ]; then
    write_log "Cannot open file '$1'"
    exit 99
fi

# if IP-list does not exist or is older than MAX_AGE, try to download new version from defined web link
if ! [ -f "$IP_FILE" ] || [ "$(expr $(date +%s) - $(date -r $IP_FILE +%s))" -gt "$MAX_AGE" ]; then
    wget "$IP_LINK" -O "$IP_FILE" &>/dev/null
    # if download failed then update time stamp of file to now or create new file if not exists, and send alert email to defined recipient
    if [ $? != 0 ]; then
        touch "$IP_FILE"
        DOMAIN_RECIPIENT="$(echo "$EMAIL_RECIPIENT"| awk -F"@" '{print $2}')"
        # if address of email alert recipient malformed then unrecoverable error
        if [ -z "$DOMAIN_RECIPIENT" ]; then
            write_log "'$EMAIL_RECIPIENT' is not a valid email address"
            exit 99
        fi
        MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
        # if cannot determine MX server for alert recipient's domain then unrecoverable error
        if [ -z "$MAIL_RELAY" ]; then
            write_log "Cannot determine mail relay for domain '$DOMAIN_RECIPIENT'"
            exit 99
        fi
        echo "Cannot download IP-list from '$IP_LINK'" | mail -s '[Check Sender IP] IP-list download failed' -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) $EMAIL_RECIPIENT
    fi
fi

# find start of first 'Received: from' in email header; if not found then unrecoverable error
RECEIVED_START="$(grep -n '^Received: from' "$1" | head -1 | cut -f1 -d\:)"
if [ -z "$RECEIVED_START" ]; then
    write_log "Cannot find 'Received from' start"
    exit 99
fi

# find end of first 'Received: from' in email header; if not found then unrecoverable error
RECEIVED_END="$(expr $RECEIVED_START + $(sed -n "$(expr $RECEIVED_START + 1),\$ p" "$1" | grep -n '^\S' | head -1 | cut -f1 -d\:) - 1)"
if [ -z "$RECEIVED_END" ]; then
    write_log "Cannot find 'Received from' end"
    exit 99
fi

# extract first 'Received: from' line; if empty then unrecoverable error
RECEIVED_LINE="$(sed -n "$RECEIVED_START,$RECEIVED_END{p}" "$1")"
if [ -z "$RECEIVED_LINE" ]; then
    write_log "Empty 'Received from' line"
    exit 99
fi

# find IP address in first 'Received: from' line; if not found then unrecoverable error
IP_ADDRESS="$(echo $RECEIVED_LINE | awk 'match($0, /\[([0-9.]+)\]/, a) {print a[1]}')"
if [ -z "$IP_ADDRESS" ]; then
    write_log 'Cannot find IP address'
    exit 99
fi

# if IP address not in IP list then error code=5
grep -q "^$IP_ADDRESS\s*$" $IP_FILE || exit 5
