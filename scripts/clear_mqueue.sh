#!/bin/bash

# clear_mqueue.sh V1.0.0
#
# Copyright (c) 2018 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

DIR_MQUEUE="/var/cs-gateway/mail/spool/mqueue_out/"
MAIL_AGE=2

find "$DIR_MQUEUE" -type f -mtime +"$MAIL_AGE" -exec rm -f {} \;
