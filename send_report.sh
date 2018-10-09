#!/bin/bash
# Clearswift SEG log analyzer
# Uwe Sommer (sommer@netcon-consulting.com)
# 10/2018
#
# logfiles for last 30 days
logfile="/var/log/cs-gateway/mail.*.log"
# Private IP Ranges
PATTERN='\[10\.'                # 10.0.0.0/8
PATTERN+='|\[192\.168\.'        # 192.168.0.0/16
for i in $(seq 16 31) ; do      # 172.16.0.0/12
    PATTERN+="|\[172\.$i\."
done
BASE() {
    # Inbound assumes private IP delivery destination
    echo "Inbound: $(grep 'relay\=' $logfile |egrep "$PATTERN" |wc -l)"
    # All destinations that are not inbound must be outbound
    echo "Outbound: $(grep 'relay\=' $logfile |grep -v "127.0.0.1" |egrep -v "$PATTERN\|smtp-watch" |wc -l)"
    # get all rejected lines
    echo "Rejected: $(grep ' 550 ' $logfile |wc -l)"
}
print_stats() {
    echo "   Mail Stats last 30 days"
    echo "============================="
    echo
    BASE |column -t
    echo
    echo "non-TLS inbound: $(grep "disconnect from" $logfile |grep "starttls=0" |wc -l)"
    grep "disconnect from" $logfile |grep "starttls=0" |awk '{print $7}' |sort |uniq -c |sort -nr |head
    echo
    echo "non-TLS outbound: $(grep postfix-outbound $logfile |grep tls_used=0 |egrep -v $PATTERN |wc -l)"
    grep postfix-outbound $logfile |grep tls_used=0 |egrep -v $PATTERN |awk '{print $7}'|awk -F "=" '{print $2}' |awk -F "[" '{print $1}'| sort |uniq -c |sort -nr |head
    echo
    echo "Top 10 recipients inbound:"
    grep 'relay\=' $logfile | egrep "$PATTERN" |awk '{ print $6 }' |sed 's/to=<//g' |tr -d "\>," |sort |uniq -c |sort -nr |head
    echo
    echo "Top 10 outbound recipients:"
    grep 'relay\=' $logfile |grep -v "127.0.0.1" |egrep -v "$PATTERN\|smtp-watch" |awk '{ print $6 }' |sed 's/to=<//g' |tr -d "\>," |sort |uniq -c |sort -nr |head
    echo
    echo "Top 10 senders:"
    grep "from=<" $logfile |grep postfix-outbound |awk '{for(i=1;i<=NF;i++){if ($i ~ /from=</) {print $i}}}' |sed 's/from=<//g' |tr -d "\>," |sed '/^$/d' |sort |uniq -c |sort -nr |head
}
if [ -z "$1" ]; then
    echo "Usage: $0 email-recipient"
    exit 1
fi
if [ -z "$(ls $logfile 2>/dev/null)" ]; then
    echo "no log files available"
    exit 2
fi
MX_SERVER=$(dig +short +nodnssec mx $(echo "$1"| awk -F"@" '{print $2}') | sort -nr | tail -1 | awk '{print $2}')
if [ -z "$MX_SERVER" ]; then
    echo "cannot find mail server"
    exit 3
fi
print_stats | mail -s "[$(hostname)] Monthly email stats report" -S smtp="$MX_SERVER:25" -r $(hostname)@$(hostname -d) "$1"
