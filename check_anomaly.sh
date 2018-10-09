#!/bin/bash
# Clearswift SEG log analyzer
# Uwe Sommer (sommer@netcon-consulting.com)
# 10/2018
#
# logfile for today
logfile="/var/log/cs-gateway/mail.$(date +"%Y-%m-%d").log"
# max mails allowed per sender per day
MAX_MAILS=500
if [ -z "$1" ]; then
    echo "Usage: $0 email-recipient"
    exit 1
fi
if [ -z "$(ls $logfile 2>/dev/null)" ]; then
    echo "no log file available"
    exit 2
fi
TOP_SENDER="$(grep "from=<" $logfile |awk '{for(i=1;i<=NF;i++){if ($i ~ /from=</) {print $i}}}' |sed 's/from=<//g' |tr -d "\>," |sed '/^$/d' |sort |uniq -c |sort -nr |head -1)"
if [ ! -z "$TOP_SENDER" ]; then
    NUM_MAILS=$(echo $TOP_SENDER | awk '{print $1}')
    if [ $NUM_MAILS -gt $MAX_MAILS ]; then
        MX_SERVER=$(dig +short +nodnssec mx $(echo "$1"| awk -F"@" '{print $2}') | sort -nr | tail -1 | awk '{print $2}')
        if [ -z "$MX_SERVER" ]; then
            echo "cannot find mail server"
            exit 3
        fi
        echo "Sender '$(echo "$TOP_SENDER" | awk '{print $2}')' has sent $NUM_MAILS mails today." | mail -s "[$(hostname)] Anomaly detection" -S smtp="$MX_SERVER:25" -r $(hostname)@$(hostname -d) "$1"
    fi
fi
