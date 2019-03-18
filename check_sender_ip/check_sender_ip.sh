#!/bin/bash

# check_sender_ip.sh V1.2.0
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

# if email file does not exist then unrecoverable error (error code=99)
[ -f "$1" ] || exit 99
# if IP-list does not exist or is older than MAX_AGE, try to download new version from defined web link
if ! [ -f "$IP_FILE" ] || [ "$(expr $(date +%s) - $(date -r $IP_FILE +%s))" -gt "$MAX_AGE" ]; then
    wget "$IP_LINK" -O "$IP_FILE" &>/dev/null
    # if download failed then update time stamp of file to now or create new file if not exists and send alert email to defined recipient
    if [ $? != 0 ]; then
        touch "$IP_FILE"
        DOMAIN_RECIPIENT="$(echo "$EMAIL_RECIPIENT"| awk -F"@" '{print $2}')"
        # if address of email alert recipient malformed then unrecoverable error (error code=99)
        [ -z "$DOMAIN_RECIPIENT" ] && exit 99
        MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
        # if cannot determine MX server for alert recipient's domain then unrecoverable error (error code=99)
        [ -z "$MAIL_RELAY" ] && exit 99
        echo "Cannot download IP-list from '$IP_LINK'" | mail -s '[Check Sender IP] IP-list download failed' -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) $EMAIL_RECIPIENT
    fi
fi
# find start of first 'Received: from' in email header; if not found then unrecoverable error (error code=99)
RECEIVED_START="$(grep -n '^Received: from' "$1" | head -1 | cut -f1 -d\:)"
[ -z "$RECEIVED_START" ] && exit 99
# find end of first 'Received: from' in email header; if not found then unrecoverable error (error code=99)
RECEIVED_END="$(expr $RECEIVED_START + $(sed -n "$(expr $RECEIVED_START + 1),\$ p" "$1" | grep -n '^\S' | head -1 | cut -f1 -d\:) - 1)"
[ -z "$RECEIVED_END" ] && exit 99
# extract first 'Received: from' line; if empty then unrecoverable error (error code=99)
RECEIVED_LINE="$(sed -n "$RECEIVED_START,$RECEIVED_END{p}" "$1")"
[ -z "$RECEIVED_LINE" ] && exit 99
# find IP address in first 'Received: from' line; if not found then unrecoverable error (error code=99)
IP_ADDRESS="$(echo $RECEIVED_LINE | awk 'match($0, /\[([0-9.]+)\]/, a) {print a[1]}')"
[ -z "$IP_ADDRESS" ] && exit 99
# if IP address in IP list then error code=0, else error code=5
grep -q "^$IP_ADDRESS\s*$" $IP_FILE || exit 5
