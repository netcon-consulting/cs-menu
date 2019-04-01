#!/bin/bash

# sender_whitelist.sh V1.0.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

USER_NAME='admin'
PASSWORD='your_CS_GUI_password_here'
DOMAIN_NAME="https://$(hostname -I | sed 's/ //')"

FILE_CONFIG='/tmp/TMPconfig.gz'
DIR_ADDRLIST='/tmp/TMPaddresslist'

WHITELIST_DOMAIN='/var/lib/rspamd/whitelist_sender_domain'
WHITELIST_EMAIL='/var/lib/rspamd/whitelist_sender_from'

get_addr_table () {
	gunzip -c "$1" | grep --color -o -P '(?<=\<AddressListTable\>).*(?=\<\/AddressListTable\>)'
}

get_addr_list () {
	get_addr_table "$1" | awk -F 'AddressList' '{for (i=1; i<=(NF+1)/2; ++i) print $(i*2)}'
}

get_addr () {
	ADDR="$(echo "$1" | awk -F 'Address' '{for (i=1; i<=(NF+1)/2; ++i) print $(i*2)}' | cut -d \> -f 2 | cut -d \< -f 1)"
	[ -z "$ADDR" ] || echo "$ADDR"
}

RESULT_LOGIN="$(curl -k -i -d "pass=$PASSWORD&submitted=true&userid=$USER_NAME" -X POST $DOMAIN_NAME/Appliance/index.jsp --silent)"

if echo "$RESULT_LOGIN" | grep -q 'you do not have permission to log in'; then
	echo "Login failure - wrong password!"
	exit 1
fi
if echo "$RESULT_LOGIN" | grep -q 'the account you are attempting to access is locked'; then
	echo "Login failure - account locked!"
	exit 2
fi

SESSION_ID="$(echo "$RESULT_LOGIN" | grep 'Set-Cookie: JSESSIONID' | awk '{print $2}')"

if [ -z "$SESSION_ID" ]; then
	echo "Cannot get session ID!"
	exit 3
fi

BACKUP_ID="$(curl --insecure --silent --header "Cookie: mswuser=$USER_NAME; $SESSION_ID" -X GET $DOMAIN_NAME/Appliance/SystemsCenter/Backup/Detail.jsp | grep '<div class="list-item" id="' | awk -F 'id="' '{print $2}' | sed 's/"//g' | head -1)"

if [ -z "$BACKUP_ID" ]; then
	echo "Cannot get backup ID!"
	exit 4
fi

curl --insecure --silent --header "Cookie: mswuser=$USER_NAME; $SESSION_ID" -X GET $DOMAIN_NAME/Appliance/Deployer/Archive?uuid="$BACKUP_ID" -o "$FILE_CONFIG"

mkdir -p "$DIR_ADDRLIST"
while read LINE; do
	if [ ! -z "$LINE" ]; then
		NAME_LIST=$(echo "$LINE" | awk -F "type=" '{print $1}' | awk -F "name=\"" '{print $2}' | tr -d \" | sed 's/ /_/g' | sed 's/_$//g')
		get_addr "$LINE" > "$DIR_ADDRLIST/$NAME_LIST.lst"
	fi
done < <(get_addr_list "$FILE_CONFIG")

LIST_DOMAIN=''
LIST_EMAIL=''

for NAME_LIST in $(ls $DIR_ADDRLIST); do
    if echo $NAME_LIST | grep -q '[wW]hitelist'; then
        LIST_DOMAIN+=" $(grep '*@' "$DIR_ADDRLIST/$NAME_LIST" | awk -F@ '{print $2}')"
        LIST_EMAIL+=" $(grep -v '*@' "$DIR_ADDRLIST/$NAME_LIST")"
    fi
done

rm -rf "$DIR_ADDRLIST" "$FILE_CONFIG"

NAME_SCRIPT="$(basename $0)"

[ -f "$WHITELIST_DOMAIN" ] && sed -i "/# start managed by $NAME_SCRIPT/,/# end managed by $NAME_SCRIPT/d" "$WHITELIST_DOMAIN"
echo "# start managed by $NAME_SCRIPT (updated $(date +%F))" >> "$WHITELIST_DOMAIN"
echo $LIST_DOMAIN | xargs -n 1 >> "$WHITELIST_DOMAIN"
echo "# end managed by $NAME_SCRIPT" >> "$WHITELIST_DOMAIN"

[ -f "$WHITELIST_EMAIL" ] && sed -i "/# start managed by $NAME_SCRIPT/,/# end managed by $NAME_SCRIPT/d" "$WHITELIST_EMAIL"
echo "# start managed by $NAME_SCRIPT (updated $(date +%F))" >> "$WHITELIST_EMAIL"
echo $LIST_EMAIL | xargs -n 1 >> "$WHITELIST_EMAIL"
echo "# end managed by $NAME_SCRIPT" >> "$WHITELIST_EMAIL"
