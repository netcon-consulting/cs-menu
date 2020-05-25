#!/usr/bin/env python3

# queue_watch.py V1.0.0
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

import enum
import sys
from pathlib import Path
from os import remove
import subprocess

"""
Check length of Postfix outbound queue. Stop Postfix inbound instance if it exceeds QUEUE_MAX, else start it if it was stopped before.
"""

PATH_QUEUE = Path("/var/spool/postfix-outbound/deferred")
PATH_STATUS = Path("/root/.smtpin_stopped")

QUEUE_MAX = 500

TEMPLATE_CMD = "source /etc/profile.d/cs-vars.sh; /opt/cs-gateway/bin/cs-servicecontrol {} smtpin &>/dev/null"

class ReturnCode(enum.IntEnum):
    """
    Return code.

    0 - ok
    1 - error
    """
    OK = 0
    ERROR = 1

def main():
    len_queue = 0

    for directory in [ str(item) for item in range(0, 10) ] + [ "A", "B", "C", "D", "E", "F" ]:
        len_queue += len([name for name in PATH_QUEUE.joinpath(directory).iterdir() if name.is_file()])

    if len_queue >= QUEUE_MAX:
        if not PATH_STATUS.exists():
            process = subprocess.Popen(TEMPLATE_CMD.format("stop"), shell=True)
            process.communicate()

            try:
                open(str(PATH_STATUS), "w").close()
            except:
                print("Cannot create status file '{}'".format(PATH_STATUS))

                return ReturnCode.ERROR
    elif PATH_STATUS.exists():
        process = subprocess.Popen(TEMPLATE_CMD.format("start"), shell=True)
        process.communicate()

        try:
            remove(str(PATH_STATUS))
        except:
            print("Cannot remove status file '{}'".format(PATH_STATUS))

            return ReturnCode.ERROR

    return ReturnCode.OK

if __name__ == "__main__":
    sys.exit(main())
