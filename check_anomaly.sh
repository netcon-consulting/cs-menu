#!/bin/bash
# Clearswift SEG log analyzer
# Uwe Sommer (sommer@netcon-consulting.com)
# 10/2018
#
# logfile for today
logfile="/var/log/cs-gateway/mail.$(date +"%Y-%m-%d").log"
# max mails allowed per sender per day
MAX_MAILS=500
MAX_RECIPIENTS=5
TMP_ANOMALY="/tmp/TMPanomaly"
if [ -z "$1" ]; then
    echo "Usage: $(basename $0) email-recipient"
    exit 1
fi
if [ -z "$(ls $logfile 2>/dev/null)" ]; then
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
    echo "$2" | mail -s "[$(hostname)] Anomaly detection" -S smtp="$MX_SERVER:25" -r $(hostname)@$(hostname -d) "$1"
}
TOP_SENDER="$(grep 'postfix-outbound' $logfile |grep "from=<" |awk '{for(i=1;i<=NF;i++){if ($i ~ /from=</) {print $i}}}' |sed 's/from=<//g' |tr -d "\>," |sed '/^$/d' |sort |uniq -c |sort -nr |head -1)"
if [ ! -z "$TOP_SENDER" ]; then
    NUM_MAILS=$(echo $TOP_SENDER | awk '{print $1}')
    if [ $NUM_MAILS -gt $MAX_MAILS ]; then
        TOP_SENDER=$(echo $TOP_SENDER | awk '{print $2}')
        TIME_STAMP="$(date +%F)"
        if [ -f "$TMP_ANOMALY" ]; then
            sed -i "/^$TIME_STAMP /"'!d' $TMP_ANOMALY
            ENTRY_BEFORE="$(grep "^[0-9-]\+ $TOP_SENDER " $TMP_ANOMALY)"
            SEND_ALERT=""
            if [ -z "$ENTRY_BEFORE" ]; then
                echo "$TIME_STAMP $TOP_SENDER $NUM_MAILS" >> $TMP_ANOMALY
                SEND_ALERT=1
            else
                NUM_BEFORE="$(echo $ENTRY_BEFORE | awk '{print $3}')"
                if [ "$(expr $NUM_MAILS - $NUM_BEFORE)" -gt $MAX_MAILS ]; then
                    sed -i "s/^$ENTRY_BEFORE/$TIME_STAMP $TOP_SENDER $NUM_MAILS/" $TMP_ANOMALY
                    SEND_ALERT=1
                fi
            fi
        else
            echo "$TIME_STAMP $TOP_SENDER $NUM_MAILS" >> $TMP_ANOMALY
            SEND_ALERT=1
        fi
        [ -z "$SEND_ALERT" ] || send_alert "$1" "Sender '$TOP_SENDER' has sent $NUM_MAILS mails today."
    fi
fi
LIST_MULTI=""
while read MULTI_SENDER; do
    SUBJECT="$(echo "$MULTI_SENDER" | awk -F '[""]' '{print $2}')"
    SENDER="$(echo "$MULTI_SENDER" | awk -F '" ' '{print $2}')"
    LIST_MULTI+=$'\n'"$SENDER \"$SUBJECT\""
done < <(grep 'postfix-inbound/cleanup.*warning: header subject:' $logfile | awk 'match($0, /warning: header subject: (.*) from /, a) match($0, / from=<([^ ]*)> /, b) {print "\""a[1]"\"",b[1]}' | sort | uniq -c | sort -nr | awk "\$1 > $MAX_RECIPIENTS {print \$0}")
[ -z "$LIST_MULTI" ] || send_alert "$1" "Senders with more than $MAX_RECIPIENTS recipients:"$'\n'"$LIST_MULTI"
