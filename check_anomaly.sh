#!/bin/bash
# check_anomaly.sh V1.1.0
#
# Copyright (c) 2018 NetCon Unternehmensberatung GmbH
# https://www.netcon-consulting.com
#
# Authors:
# Uwe Sommer (u.sommer@netcon-consulting.com)
# Dr. Marc Dierksen (m.dierksen@netcon-consulting.com)

LOG_FILE="/var/log/cs-gateway/mail.$(date +"%Y-%m-%d").log"
MAX_MAILS=500 # max mails allowed per sender per day
MAX_RECIPIENTS=5 # max recipients allowed per mail
TMP_MAILS='/tmp/TMPmails'
TMP_RECIPIENTS='/tmp/TMPrecipients'
CONFIG_WHITELIST='/etc/anomaly_whitelist.conf'
NAME_DOMAIN_DEFAULT='isdoll.de'
if [ -z "$1" ]; then
    echo "Usage: $(basename $0) email-recipient"
    exit 1
fi
if ! [ -f "$LOG_FILE" ]; then
    echo "no log file available"
    exit 2
fi
# $1 - recipient
# $2 - message
send_alert() {
    MX_SERVER=$(dig +short +nodnssec mx $(echo "$1"| awk -F"@" '{print $2}') | sort -nr | tail -1 | awk '{print $2}')
    if [ -z "$MX_SERVER" ]; then
        echo "cannot find mail server"
        exit 3
    fi
    NAME_DOMAIN="$(hostname -d)"
    [ -z "$NAME_DOMAIN" ] && NAME_DOMAIN="$NAME_DOMAIN_DEFAULT"
    echo "$2" | mail -s "[$(hostname)] Anomaly detection" -S smtp="$MX_SERVER:25" -r "$(hostname)@$NAME_DOMAIN" "$1"
}
TIME_STAMP="$(date +%F)"
[ -f "$TMP_MAILS" ] && sed -i "/^$TIME_STAMP /"'!d' $TMP_MAILS
[ -f "$TMP_RECIPIENTS" ] && sed -i "/^$TIME_STAMP /"'!d' $TMP_RECIPIENTS
LIST_SENDER=""
while read INFO_SENDER; do
    SENDER=$(echo $INFO_SENDER | awk '{print $2}')
    if ! [ -f "$CONFIG_WHITELIST" ] || ! grep -q "^$SENDER$" $CONFIG_WHITELIST; then
        NUM_MAILS=$(echo $INFO_SENDER | awk '{print $1}')
        SEND_ALERT=""
        if [ -f "$TMP_MAILS" ]; then
            ENTRY_BEFORE="$(grep "^[0-9-]\+ $SENDER " $TMP_MAILS)"
            if [ -z "$ENTRY_BEFORE" ]; then
                echo "$TIME_STAMP $SENDER $NUM_MAILS" >> $TMP_MAILS
                SEND_ALERT=1
            else
                NUM_BEFORE="$(echo $ENTRY_BEFORE | awk '{print $3}')"
                if [ "$(expr $NUM_MAILS - $NUM_BEFORE)" -gt $MAX_MAILS ]; then
                    sed -i "s/^$ENTRY_BEFORE/$TIME_STAMP $SENDER $NUM_MAILS/" $TMP_MAILS
                    SEND_ALERT=1
                fi
            fi
        else
            echo "$TIME_STAMP $SENDER $NUM_MAILS" >> $TMP_MAILS
            SEND_ALERT=1
        fi
        [ -z "$SEND_ALERT" ] || LIST_SENDER+=$'\n'"$SENDER $NUM_MAILS"
    fi
done < <(grep 'postfix-outbound' $LOG_FILE | grep "from=<" | awk '{for(i=1;i<=NF;i++){if ($i ~ /from=</) {print $i}}}' | sed 's/from=<//g' | tr -d "\>," | sed '/^$/d' | sort | uniq -c | sort -nr | awk "\$1 > $MAX_MAILS {print \$0}")
[ -z "$LIST_SENDER" ] || send_alert "$1" "Senders with more than $MAX_MAILS mails:"$'\n'"$LIST_SENDER"
LIST_SENDER=""
while read INFO_SENDER; do
    SENDER="$(echo "$INFO_SENDER" | awk -F '" ' '{print $2}')"
    if ! [ -f "$CONFIG_WHITELIST" ] || ! grep -q "^$SENDER$" $CONFIG_WHITELIST; then
        SUBJECT="$(echo "$INFO_SENDER" | awk -F '[""]' '{print $2}')"
        SEND_ALERT=""
        if [ -f "$TMP_RECIPIENTS" ]; then
            ENTRY_BEFORE="$(grep "^[0-9-]\+ $SENDER $SUBJECT$" $TMP_RECIPIENTS)"
            if [ -z "$ENTRY_BEFORE" ]; then
                echo "$TIME_STAMP $SENDER $SUBJECT" >> $TMP_RECIPIENTS
                SEND_ALERT=1
            fi
        else
            echo "$TIME_STAMP $SENDER $SUBJECT" >> $TMP_RECIPIENTS
            SEND_ALERT=1
        fi
        [ -z "$SEND_ALERT" ] || LIST_SENDER+=$'\n'"$SENDER \"$SUBJECT\""
    fi
done < <(grep 'postfix-inbound/cleanup.*warning: header subject:' $LOG_FILE | awk 'match($0, /warning: header subject: (.*) from /, a) match($0, / from=<([^ ]*)> /, b) {print "\""a[1]"\"",b[1]}' | sort | uniq -c | sort -nr | awk "\$1 > $MAX_RECIPIENTS {print \$0}")
[ -z "$LIST_SENDER" ] || send_alert "$1" "Senders with more than $MAX_RECIPIENTS recipients:"$'\n'"$LIST_SENDER"
