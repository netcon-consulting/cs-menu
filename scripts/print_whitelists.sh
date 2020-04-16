#!/bin/bash

# print_whitelists.sh V1.1.0
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

DIR_ADDRESS='/var/cs-gateway/uicfg/policy/addresslists'

for FILE_ADDRESS in $(grep -P -l 'AddressList name="[^"]*(?i)(whitelist|partner)[^"]*"' $DIR_ADDRESS/*.xml 2>/dev/null); do
    xmlstarlet sel -t -m "AddressList/Address" -v . -n "$FILE_ADDRESS" 2>/dev/null | sed '/^$/d'
done
