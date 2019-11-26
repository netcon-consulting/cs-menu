#!/bin/bash

# dkim_report.sh V1.1.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

TRANSPORT_MAP='/etc/postfix-outbound/transport.map'
DKIM_LOG="/tmp/dkim-$(date +'%Y-%m' -d yesterday).log"

CSV_SEPERATOR=';'

if [ -z "$1" ]; then
    echo "Usage: $(basename $0) email_recipient"
    exit 1
fi

LIST_CSV="$(awk "match(\$0, /from=(.*), to=(.*), subject=.*, dkim_domain=(.*), dkim_selector=(.*)/,a) {print a[1]\"${CSV_SEPERATOR}\"a[2]\"${CSV_SEPERATOR}\"a[3]\"${CSV_SEPERATOR}\"a[4]}" "$DKIM_LOG" | sort | uniq -c | sort -nr | awk "match(\$0, /^[ ]*([0-9]+) (.*)/,a) {print a[1]\"${CSV_SEPERATOR}\"a[2]}")"

if ! [ -z "$LIST_CSV" ]; then
    DOMAIN_RECIPIENT="$(echo "$1"| awk -F"@" '{print $2}')"
    MAIL_RELAY=''
    [ -f "$TRANSPORT_MAP" ] && MAIL_RELAY="$(grep "^$DOMAIN_RECIPIENT " $TRANSPORT_MAP | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
    [ -z "$MAIL_RELAY" ] && MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
    if [ -z "$MAIL_RELAY" ]; then
        echo "Cannot determine mail relay"
        exit 1
    else
        LIST_CSV="number${CSV_SEPERATOR}from${CSV_SEPERATOR}to${CSV_SEPERATOR}dkim_domain${CSV_SEPERATOR}dkim_selector"$'\n'"$LIST_CSV"

        echo "$LIST_CSV" | mail -s "[DKIM-report] Report from $(date +%F)" -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) "$1"
    fi
fi
