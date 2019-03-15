#!/bin/bash

# remove_external.sh V1.2.1
#
# Copyright (c) 2018 NetCon Unternehmensberatung GmbH, info@netcon-consulting.com
#
# Authors: Uwe Sommer, Marc Dierksen

# return codes:
# 0 - not modified
# 5 - modified

MODIFIED=''
if [ -f "$1" ]; then
    # remove 'EXT' tag from 'To:' line
    if grep -q '^\(T\|t\)o: "\[EXT\] ' "$1"; then
        sed -i 's/^\(T\|t\)o: "\[EXT\] /\1o: "/' "$1"
        MODIFIED=1
    fi
    # remove 'EXT' tag from 'CC:' line
    if grep -q '^\(\(C\|c\)\{2\}\): "\[EXT\] ' "$1"; then
        sed -i 's/^\(\(C\|c\)\{2\}\): "\[EXT\] /\1: "/' "$1"
        MODIFIED=1
    fi
fi
# if modified error code=5, else error code=0
[ "$MODIFIED" = 1 ] && exit 5 || exit 0
