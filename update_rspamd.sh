#!/bin/bash

# update_rspamd.sh V1.0.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

TRANSPORT_MAP='/etc/postfix-outbound/transport.map'

EMAIL_RECIPIENT='uwe@usommer.de'

yum check-update rspamd &>/dev/null
if [ "$?" != 0 ]; then
    yum update -y rspamd &>/dev/null
    if [ "$?" = 0 ]; then
        MESSAGE_EMAIL="Rspamd successfully updated to version '$(yum list rspamd | grep rspamd | awk '{print $2}')'"
    else
        MESSAGE_EMAIL='Error updating rspamd'
    fi
    DOMAIN_RECIPIENT="$(echo "$EMAIL_RECIPIENT"| awk -F"@" '{print $2}')"
    MAIL_RELAY=''
    [ -f "$TRANSPORT_MAP" ] && MAIL_RELAY="$(grep "^$DOMAIN_RECIPIENT " $TRANSPORT_MAP | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
    [ -z "$MAIL_RELAY" ] && MAIL_RELAY="$(dig +short +nodnssec mx $DOMAIN_RECIPIENT | sort -nr | tail -1 | awk '{print $2}')"
    if [ -z "$MAIL_RELAY" ]; then
        echo "Cannot determine mail relay"
        exit 1
    else
        echo "$MESSAGE_EMAIL" | mail -s "[Rspamd-update] $MESSAGE_EMAIL" -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) "$EMAIL_RECIPIENT"
    fi
fi
