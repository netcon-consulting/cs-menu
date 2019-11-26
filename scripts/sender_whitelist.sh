#!/bin/bash

# sender_whitelist.sh V1.6.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

DIR_ADDRLIST='/tmp/TMPaddresslist'

LAST_CONFIG='/var/cs-gateway/deployments/lastAppliedConfiguration.xml'

WHITELIST_DOMAIN='/var/lib/rspamd/whitelist_sender_domain'
WHITELIST_FROM='/var/lib/rspamd/whitelist_sender_from'

TMP_DOMAIN='/tmp/TMPdomain'
TMP_FROM='/tmp/TMPfrom'

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
		NAME_LIST=$(echo "$LINE" | awk 'match($0, /name="([^"]+)"/, a) {print a[1]}' | sed 's/ /_/g')
		get_addr "$LINE" > "$DIR_ADDRLIST/$NAME_LIST.lst"
	fi
done < <(get_addr_list)

rm -f "$TMP_DOMAIN" "$TMP_FROM"

for NAME_LIST in $(ls $DIR_ADDRLIST); do
    if echo $NAME_LIST | grep -q '[wW][hH][iI][tT][eE][lL][iI][sS][tT]'; then
        grep '*@' "$DIR_ADDRLIST/$NAME_LIST" | awk -F@ '{print $2}' >> "$TMP_DOMAIN"
        grep -v '*@' "$DIR_ADDRLIST/$NAME_LIST" >> "$TMP_FROM"
    fi
done

NAME_SCRIPT="$(basename $0)"

[ -f "$WHITELIST_DOMAIN" ] && sed -i "/# start managed by $NAME_SCRIPT/,/# end managed by $NAME_SCRIPT/d" "$WHITELIST_DOMAIN"
[ -f "$WHITELIST_FROM" ] && sed -i "/# start managed by $NAME_SCRIPT/,/# end managed by $NAME_SCRIPT/d" "$WHITELIST_FROM"

DATE_CURRENT="$(date +%F)"

echo "# start managed by $NAME_SCRIPT (updated $DATE_CURRENT)" >> "$WHITELIST_DOMAIN"
[ -f "$TMP_DOMAIN" ] && sort -u "$TMP_DOMAIN" >> "$WHITELIST_DOMAIN"
echo "# end managed by $NAME_SCRIPT" >> "$WHITELIST_DOMAIN"

echo "# start managed by $NAME_SCRIPT (updated $DATE_CURRENT)" >> "$WHITELIST_FROM"
[ -f "$TMP_FROM" ] && sort -u "$TMP_FROM" >> "$WHITELIST_FROM"
echo "# end managed by $NAME_SCRIPT" >> "$WHITELIST_FROM"

chown _rspamd:_rspamd "$WHITELIST_DOMAIN" "$WHITELIST_FROM"

rm -rf "$DIR_ADDRLIST" "$TMP_DOMAIN" "$TMP_FROM"
