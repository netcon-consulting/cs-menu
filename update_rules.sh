#!/bin/bash

# update_rules.sh V1.0.0
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

    service rspamd restart &>/dev/null
fi
