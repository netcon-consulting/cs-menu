#!/bin/bash

# email_backup.sh V1.0.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

LAST_CONFIG='/var/cs-gateway/deployments/lastAppliedConfiguration.xml'
TRANSPORT_MAP='/etc/postfix-outbound/transport.map'

EMAIL_RECIPIENT='__EMAIL_RECIPIENT__'
NAME_BACKUP='CS_config_'

DATE_CURRENT="$(date +%F)"

FILE_BACKUP="/tmp/$NAME_BACKUP$DATE_CURRENT"

cp -f "$LAST_CONFIG" "$FILE_BACKUP"
gzip "$FILE_BACKUP"
mv -f "$FILE_BACKUP.gz" "$FILE_BACKUP.bk"

FILE_BACKUP+='.bk'

DOMAIN_RECIPIENT="$(echo "$EMAIL_RECIPIENT"| awk -F"@" '{print $2}')"
MAIL_RELAY=''
[ -f "$TRANSPORT_MAP" ] && MAIL_RELAY="$(grep "^$DOMAIN_RECIPIENT " $TRANSPORT_MAP | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
[ -z "$MAIL_RELAY" ] && MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
if [ -z "$MAIL_RELAY" ]; then
    echo "Cannot determine mail relay"
    exit 1
else
    echo "[CS-backup] CS config from $DATE_CURRENT" | mail -s "[CS-backup] CS config from $DATE_CURRENT" -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) -a "$FILE_BACKUP" "$EMAIL_RECIPIENT"
fi

rm -f "$FILE_BACKUP"
