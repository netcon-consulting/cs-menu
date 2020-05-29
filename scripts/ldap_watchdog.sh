#!/bin/bash

# ldap_watchdog.sh V1.7.0
#
# Copyright (c) 2018-2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

. /etc/profile.d/cs-vars.sh

DIR_LDAP='/var/cs-gateway/ldap'
TRANSPORT_MAP='/etc/postfix-outbound/transport.map'
TMP_LDAP='/tmp/TMPldap'
DURATION_MAX='300'
EMAIL_RECIPIENT='__EMAIL_RECIPIENT__'

TIME_NOW="$(date +%s)"

LIST_NAME=''
LIST_FILE=''

for FILE in $(ls $DIR_LDAP/state/* | grep -v 'last$'); do
    STATE="$(awk 'match($0, /state="([a-z]*)"/, a) {print a[1]}' "$FILE")"
    TIME_TRY="$(awk 'match($0, /lastTried="([0-9]*)"/, a) {print a[1]}' "$FILE")"
    TIME_SUCCESS="$(awk 'match($0, /lastSuccess="([0-9]*)"/, a) {print a[1]}' "$FILE")"

    if [ "$TIME_TRY" != "$TIME_SUCCESS" ]; then
        if [ "$STATE" != "inprogress" ] || [ "$(expr "$TIME_NOW" - $(echo "$TIME_TRY" | sed 's/.\{3\}$//'))" -gt "$DURATION_MAX" ]; then
            FILE_NAME="$(echo $FILE | awk -F/ '{print $NF}')"
            LIST_FILE+=" $FILE_NAME"
            LIST_NAME+=$'\n'"$(awk 'match($0, /<AddressList[^>]*name="([^"]*)"/, a) {print a[1]}' "$DIR_LDAP/scheduled/$FILE_NAME")"
        fi
    fi
done

if ! [ -z "$LIST_NAME" ]; then
    if ! [ -f "$TMP_LDAP" ] || [ "$(cat "$TMP_LDAP")" != "$(date +%F)" ]; then
        LIST_NAME="Syncing LDAP list failed for:"$'\n'"$LIST_NAME"

        DOMAIN_RECIPIENT="$(echo "$EMAIL_RECIPIENT"| awk -F"@" '{print $2}')"
        MAIL_RELAY=""
        [ -f "$TRANSPORT_MAP" ] && MAIL_RELAY="$(grep "^$DOMAIN_RECIPIENT " "$TRANSPORT_MAP" | awk '{print $2}' | awk -F '[\\[\\]]' '{print $2}')"
        [ -z "$MAIL_RELAY" ] && MAIL_RELAY="$(dig +short +nodnssec mx "$DOMAIN_RECIPIENT" | sort -nr | tail -1 | awk '{print $2}')"
        if [ -z "$MAIL_RELAY" ]; then
            echo "Cannot determine mail relay"
            exit 1
        else
            echo "$LIST_NAME" | mail -s '[LDAP-Watchdog] Sync LDAP failed' -S smtp="$MAIL_RELAY:25" -r $(hostname)@$(hostname -d) "$EMAIL_RECIPIENT"
        fi

        date +%F > "$TMP_LDAP"
    fi

    kill "$(pidof LdapAgent)" >/dev/null 2>&1

    /opt/cs-gateway/bin/cs-servicecontrol restart ldap

    for NAME_FILE in LIST_FILE; do
        cp -r "$DIR_LDAP/scheduled/$FILE_NAME" "$DIR_LDAP/pending/$FILE_NAME"
    done
fi
