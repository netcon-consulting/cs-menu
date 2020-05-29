#!/usr/bin/env python3

# queue_watch.py V1.1.0
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

import argparse
import enum
import sys
from pathlib import Path
from os import remove
from subprocess import Popen, PIPE, DEVNULL
import re

DESCRIPTION = "automatic manangement for temporary suspension of Postfix inbound instance depending on length of Postfix outbound queue"

PATH_QUEUE = Path("/var/spool/postfix-outbound/deferred")
PATH_STATUS = Path("/root/.smtpin_stopped")

QUEUE_UPPER = 500
QUEUE_LOWER = 100

TEMPLATE_CMD = "source /etc/profile.d/cs-vars.sh; /opt/cs-gateway/bin/cs-servicecontrol {} smtpin"

STATUS_RUNNING = "running"
STATUS_STOPPED = "stopped"

PATTERN_STATUS = re.compile(r"^SMTP Inbound Transport is ({}|{})\n$".format(STATUS_RUNNING, STATUS_STOPPED))

class ReturnCode(enum.IntEnum):
    """
    Return code.

    0 - ok
    1 - error
    """
    OK = 0
    ERROR = 1

class StatusSmtpin(enum.IntEnum):
    """
    Status of postfix-inbound instance.

    0 - stopped
    1 - running
    """
    STOPPED = 0
    RUNNING = 1

def status_smtpin():
    """
    Check status of postfix-inbound instance.

    :rtype: StatusSmtpin
    """
    process = Popen(TEMPLATE_CMD.format("status"), stdout=PIPE, stderr=DEVNULL, shell=True)

    (stdout, _) = process.communicate()

    match = re.match(PATTERN_STATUS, stdout.decode("utf-8"))

    if match:
        status = match.group(1)

        if status == STATUS_RUNNING:
            return StatusSmtpin.RUNNING
        elif status == STATUS_STOPPED:
            return StatusSmtpin.STOPPED
        else:
            raise Exception("Invalid postfix-inbound status '{}'".format(status))
    else:
        raise Exception("Cannot determine postfix-inbound status")

def main(args):
    try:
        status = status_smtpin()
    except Exception as ex:
        print(ex)

        return ReturnCode.ERROR

    smtpin_stopped = bool(status == StatusSmtpin.STOPPED)

    statusfile_exists = PATH_STATUS.exists()

    if smtpin_stopped and not statusfile_exists:
        return ReturnCode.OK

    if not smtpin_stopped and statusfile_exists:
        remove(str(PATH_STATUS))

    len_queue = 0

    for directory in [ str(item) for item in range(0, 10) ] + [ "A", "B", "C", "D", "E", "F" ]:
        len_queue += len([item for item in PATH_QUEUE.joinpath(directory).iterdir() if item.is_file()])

    if len_queue >= args.upper and not smtpin_stopped:
        Popen(TEMPLATE_CMD.format("stop"), stdout=DEVNULL, stderr=DEVNULL, shell=True).communicate()

        try:
            open(str(PATH_STATUS), "w").close()
        except:
            print("Cannot create status file '{}'".format(PATH_STATUS))

            return ReturnCode.ERROR
    elif len_queue < args.lower and smtpin_stopped:
        Popen(TEMPLATE_CMD.format("start"), stdout=DEVNULL, stderr=DEVNULL, shell=True).communicate()

        try:
            remove(str(PATH_STATUS))
        except:
            print("Cannot remove status file '{}'".format(PATH_STATUS))

            return ReturnCode.ERROR

    return ReturnCode.OK

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument("-l", "--lower", metavar="LOWER", type=int, default=QUEUE_LOWER,
        help="lower limit of Postfix outbound queue at which the Postfix inbound suspension be lifted (default={})".format(QUEUE_LOWER))
    parser.add_argument("-u", "--upper", metavar="UPPER", type=int, default=QUEUE_UPPER,
        help="upper limit of Postfix outbound queue at which the Postfix inbound instance will be suspended (default={})".format(QUEUE_UPPER))

    args = parser.parse_args()

    sys.exit(main(args))
