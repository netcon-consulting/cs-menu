#!/bin/bash

# clean_psql.sh V1.0.0
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, netcon-consulting.com
#
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

/opt/rh/rh-postgresql96/root/usr/bin/psql -U postgres -c 'VACUUM' &>/dev/null
