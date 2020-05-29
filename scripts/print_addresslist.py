#!/usr/bin/env python3

# print_addresslist.py V1.1.0
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

import argparse
import enum
import sys
import re
from xml.sax import make_parser, handler, SAXException

DESCRIPTION = "print address lists, optionally filtered by regex matches on list name and email address"

REGEX_LIST = ".*"
REGEX_EMAIL = ".*"

LAST_CONFIG = "/var/cs-gateway/deployments/lastAppliedConfiguration.xml"

class ReturnCode(enum.IntEnum):
    """
    Return code.

    0 - ok
    1 - error
    """
    OK = 0
    ERROR = 1

class SAXExceptionFinished(SAXException):
    """
    Custom SAXException for stopping parsing after all info has been read.
    """
    def __init__(self):
        super().__init__("Stop parsing")

class HandlerAddressList(handler.ContentHandler):
    """
    Custom content handler for xml.sax for extracting address lists from CS config filtered by regex matches on list name and email address.
    """
    def __init__(self, regex_list, regex_email):
        """
        :type regex_list: str
        :type regex_email: str
        """
        self.pattern_list = re.compile(regex_list)
        self.pattern_email = re.compile(regex_email)
        self.list_addresslist = list()
        self.name_list = ""
        self.add_address = False
        self.list_address = None

        super().__init__()

    def startElement(self, name, attrs):
        if not self.add_address:
            if name == "AddressList" and "name" in attrs:
                name_list = attrs["name"]

                if re.search(self.pattern_list, name_list):
                    self.name_list = name_list
            elif self.name_list and name == "Address":
                self.list_address = list()
                self.add_address = True

    def characters(self, content):
        if self.add_address:
            if re.search(self.pattern_email, content):
                self.list_address.append(content)

    def endElement(self, name):
        if name == "AddressList" and self.add_address:
            if self.list_address:
                self.list_addresslist.append(( self.name_list, self.list_address ))

            self.name_list = ""
            self.add_address = False
        elif name == "AddressListTable":
            raise SAXExceptionFinished

    def getAddressLists(self):
        """
        Return list of address lists.

        :rtype: list
        """
        return self.list_addresslist

def get_address_list(regex_list, regex_email, last_config=LAST_CONFIG):
    """
    Extract address lists from CS config filtered by regex matches on list name and email address.

    :type regex_list: str
    :type regex_email: str
    :type last_config: str
    :rtype: list
    """
    parser = make_parser()
    address_handler = HandlerAddressList(regex_list, regex_email)
    parser.setContentHandler(address_handler)

    try:
        parser.parse(last_config)
    except SAXExceptionFinished:
        pass

    return address_handler.getAddressLists()

def main(args):
    try:
        list_addresslist = get_address_list(args.list_regex, args.email_regex)
    except Exception as ex:
        print(ex)

        return ReturnCode.ERROR

    for (name_list, list_address) in sorted(list_addresslist):
        if list_address:
            print("### {} ###".format(name_list))

            for address in sorted(list_address):
                print(address)

            print("")

    return ReturnCode.OK

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    parser.add_argument("-l", "--list-regex", metavar="LIST_REGEX", type=str, default=REGEX_LIST, help="regex for filtering list names (default={})".format(REGEX_LIST))
    parser.add_argument("-e", "--email-regex", metavar="EMAIL_REGEX", type=str, default=REGEX_EMAIL, help="regex for filtering email addresses (default={})".format(REGEX_EMAIL))

    args = parser.parse_args()

    sys.exit(main(args))
