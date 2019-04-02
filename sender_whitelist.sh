#!/bin/bash

# sender_whitelist.sh V1.2.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

DIR_ADDRLIST='/tmp/TMPaddresslist'

LAST_CONFIG='/var/cs-gateway/deployments/lastAppliedConfiguration.xml'

WHITELIST_DOMAIN='/var/lib/rspamd/whitelist_sender_domain'
WHITELIST_EMAIL='/var/lib/rspamd/whitelist_sender_from'

get_addr_table () {
	[ -f "$LAST_CONFIG" ] && cat "$LAST_CONFIG" | grep -o -P '(?<=\<AddressListTable\>).*(?=\<\/AddressListTable\>)'
}

get_addr_list () {
	get_addr_table "$1" | awk -F 'AddressList' '{for (i=1; i<=(NF+1)/2; ++i) print $(i*2)}'
}

get_addr () {
	ADDR="$(echo "$1" | awk -F 'Address' '{for (i=1; i<=(NF+1)/2; ++i) print $(i*2)}' | cut -d \> -f 2 | cut -d \< -f 1)"
	[ -z "$ADDR" ] || echo "$ADDR"
}

mkdir -p "$DIR_ADDRLIST"
while read LINE; do
	if [ ! -z "$LINE" ]; then
		NAME_LIST=$(echo "$LINE" | awk -F "type=" '{print $1}' | awk -F "name=\"" '{print $2}' | tr -d \" | sed 's/ /_/g' | sed 's/_$//g')
		get_addr "$LINE" > "$DIR_ADDRLIST/$NAME_LIST.lst"
	fi
done < <(get_addr_list)

LIST_DOMAIN=''
LIST_EMAIL=''

for NAME_LIST in $(ls $DIR_ADDRLIST); do
    if echo $NAME_LIST | grep -q '[wW][hH][iI][tT][eE][lL][iI][sS][tT]'; then
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

chown _rspamd:_rspamd "$WHITELIST_DOMAIN" "$WHITELIST_EMAIL"
