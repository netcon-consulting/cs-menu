#!/bin/bash

# update_rules.sh V1.1.0
#
# Copyright (c) 2019 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

DIR_RULES='/tmp/TMPrules'
FILE_RULES='/etc/rspamd/local.d/spamassassin.rules'

VERSION_RULES="$(dig txt 2.4.3.spamassassin.heinlein-support.de +short | tr -d '"')"

if [ -z "$VERSION_RULES" ]; then
    echo 'Cannot determine SA rules version'
    exit 1
fi

FILE_DOWNLOAD="$DIR_RULES/$VERSION_RULES.tgz"

if ! [ -f "$FILE_DOWNLOAD" ]; then
    mkdir -p "$DIR_RULES"
    rm -f $DIR_RULES/*
    curl --silent "http://www.spamassassin.heinlein-support.de/$VERSION_RULES.tar.gz" --output "$FILE_DOWNLOAD"

    if ! [ -f "$FILE_DOWNLOAD" ]; then
        echo 'Cannot download SA rules'
        exit 2
    fi

    tar -C "$DIR_RULES" -xzf "$FILE_DOWNLOAD"
    cat $DIR_RULES/*.cf > "$FILE_RULES"

    PACKED_SCRIPT='
    H4sIAAJ2sFwAA3WS0WqDMBSG732KQKG0F85d7WIwWJ1jLTpadC0bFCTRo4a2UXKSsRXZ0+xN9mKL
    LQzt9MBJwpf8Iec/GY3IBiTypACpRY4kqujBKoCmIEkcB8uHWRCv/E0898J45q6jR9LEqx1CVUpl
    z5hGIHdfxKHN6t4Z0gaL6OUkJfDBUeFtYEZ7LVAzTCRnMCT0/MVzR9gAO+K5oEpLsFiZfnZE7tJ7
    I61wtmxieP1k0p2bBCU5MCxopqpsb0pXfey9ZUu9yvaQw1EjVcfOhi+p2IHoMNdMGWqR/XwXPN8B
    V3UIQl2cOl/ZRtMtc7h1AEXJXzXkf0z62zIe93vew0+WXvDGtamVwrkZgw/o+SyYlHJYYOLm6tr6
    Baleg75oAgAA
    '
    printf "%s" $PACKED_SCRIPT | base64 -d | gunzip >> "$FILE_RULES"

    service rspamd restart &>/dev/null
fi
