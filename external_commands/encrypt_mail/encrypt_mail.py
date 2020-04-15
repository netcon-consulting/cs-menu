#!/usr/bin/env python3

# encrypt_mail.py V1.0.0
#
# Copyright (c) 2020 NetCon Unternehmensberatung GmbH, https://www.netcon-consulting.com
# Author: Marc Dierksen (m.dierksen@netcon-consulting.com)

import enum
import argparse
import sys
from collections import namedtuple
from email import message_from_string
import toml

#########################################################################################

import re
from io import BytesIO
import random
import string
from email.message import EmailMessage
import smtplib
import pyzipper

DESCRIPTION = "zip-encrypts email if keyword present in subject, sends it to recipients and generated password to sender"

class ReturnCode(enum.IntEnum):
    """ReturnCode

    0  - encryption skipped
    1  - mail encrypted
    99 - error
    """
    ENCRYPTION_SKIPPED = 0
    MAIL_ENCRYPTED = 1
    ERROR = 99

CONFIG_PARAMETERS = ( "keyword_encryption", "password_length", "password_punctuation" )

MESSAGE_RECIPIENT="You have received an encrypted email from {} attached to this email.\n\nThe password will be provided to you by the sender shortly.\n\nHave a nice day."
MESSAGE_SENDER="The email has been encrypted with the password {} and sent.\n\nPlease provide the recipients with the password.\n\nHave a nice day."

PORT_SMTP=10026

def zip_encrypt(set_data, password):
    """create encrypted zip archive with defined password and return as bytes

    args:
        set_data - { (str, bytes) }
        password - str
    """
    buffer = BytesIO()

    with pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_LZMA, encryption=pyzipper.WZ_AES) as zf:
        zf.pwd = password

        for (file_name, data) in set_data:
            zf.writestr(file_name, data)

    return buffer.getvalue()

def main(args):
    try:
        config = read_config(args.config)

        email_raw = read_file(args.email)
    except Exception as ex:
        write_log(ex, args.log)

        return ReturnCode.ERROR

    try:
        email_parsed = message_from_string(email_raw)
    except:
        write_log("Cannot parse email", args.log)

        return ReturnCode.ERROR

    header_subject = email_parsed.get("Subject")

    if not header_subject or not re.match(r"^{}".format(config.keyword_encryption), header_subject, re.I):
        return ReturnCode.ENCRYPTION_SKIPPED

    header_from = email_parsed.get("From")

    if not header_from:
        write_log("Header from is empty", args.log)

        return ReturnCode.ERROR

    address_sender = re.search(r'.*?([^<",;\s]+@[^>",;\s]+)', header_from, re.A)

    if not address_sender:
        write_log("Cannot find sender address", args.log)

        return ReturnCode.ERROR

    address_sender = address_sender.group(1)

    address_recipient = dict()

    # collect email addresses in To and Cc headers
    for header_keyword in [ "To", "Cc" ]:
        address_recipient[header_keyword] = set()

        list_header = email_parsed.get_all(header_keyword)

        if list_header:
            for header in list_header:
                result = re.findall(r'.*?([^<",;\s]+@[^>",;\s]+)', header, re.A)

                if result:
                    address_recipient[header_keyword] |= set(result)

    if not address_recipient["To"]:
        write_log("Cannot find recipient address", args.log)

        return ReturnCode.ERROR

    # remove encryption keyword from subject header
    email_raw = re.sub(r"(\n|^)Subject: *{} *".format(config.keyword_encryption), r"\1Subject: ", email_raw, count=1, flags=re.I)
    header_subject = re.sub(r"^{} *".format(config.keyword_encryption), "", header_subject, flags=re.I)

    password_characters = string.ascii_letters + string.digits
    if config.password_punctuation:
        password_characters += string.punctuation
    password = ''.join(random.choice(password_characters) for i in range(config.password_length))

    try:
        zip_archive = zip_encrypt({ ("email.eml", email_raw) }, password)
    except:
        write_log("Error zip-encrypting email", args.log)

        return ReturnCode.ERROR

    # send email with encrypted original mail attached to recipients
    email_message = EmailMessage()
    email_message["Subject"] = header_subject
    email_message["From"] = address_sender
    email_message["To"] = ", ".join(address_recipient["To"])
    if address_recipient["Cc"]:
        email_message["Cc"] = ", ".join(address_recipient["Cc"])
    email_message.set_content(MESSAGE_RECIPIENT.format(address_sender))
    email_message.add_attachment(zip_archive, maintype="application", subtype="zip", filename="email.zip")
    
    try:
        with smtplib.SMTP("localhost", port=PORT_SMTP) as s:
            s.send_message(email_message)
    except:
        write_log("Cannot send recipient email", args.log)

        return ReturnCode.ERROR

    # send email with password to sender
    email_message = EmailMessage()
    email_message["Subject"] = "Re: {}".format(header_subject)
    email_message["From"] = address_sender
    email_message["To"] = address_sender
    email_message.set_content(MESSAGE_SENDER.format(password))

    try:
        with smtplib.SMTP("localhost", port=PORT_SMTP) as s:
            s.send_message(email_message)
    except:
        write_log("Cannot send sender email", args.log)

    return ReturnCode.MAIL_ENCRYPTED

#########################################################################################

LOG_PREFIX = ">>>>"
LOG_SUFFIX = "<<<<"

def read_file(path_file):
    """read file as text
    
    args:
        path_file - str
    """
    try:
        with open(path_file) as f:
            content = f.read()
    except FileNotFoundError:
        raise Exception("'{}' does not exist".format(path_file))
    except PermissionError:
        raise Exception("Cannot open '{}'".format(path_file))
    except UnicodeDecodeError:
        raise Exception("'{}' not UTF-8".format(path_file))

    return content

def read_email(path_email):
    """read email file and parse contents
    
    args:
        path_email - str
    """
    email = read_file(path_email)

    try:
        email = message_from_string(email)
    except:
        raise Exception("Cannot parse email")

    return email

def read_config(path_config):
    """read config file and check all required config parameters are defined

    args:
        path_config - str
    """
    config = read_file(path_config)

    try:
        config = toml.loads(config)
    except:
        raise Exception("Cannot parse config")

    # discard all parameters not defined in CONFIG_PARAMETERS
    config = { param_key: param_value for (param_key, param_value) in config.items() if param_key in CONFIG_PARAMETERS }

    # check for missing parameters
    parameters_missing = CONFIG_PARAMETERS - config.keys()

    if parameters_missing:
        raise Exception("Missing parameters {}".format(str(parameters_missing)[1:-1]))

    TupleConfig = namedtuple('TupleConfig', CONFIG_PARAMETERS)

    return TupleConfig(**config)

def write_log(message, path_log):
    """write message to log file

    args:
        message - str
        path_log - str
    """
    with open(path_log, "a") as file_log:
        file_log.write("{}{}{}\n".format(LOG_PREFIX, message, LOG_SUFFIX))

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=DESCRIPTION)

    if __file__.endswith(".py"):
        config_default = __file__[:-3] + ".toml"
    else:
        config_default = __file__ + ".toml"

    parser.add_argument(
        "-c",
        "--config",
        metavar="CONFIG",
        type=str,
        default=config_default,
        help="path to configuration file (default={})".format(config_default)
    )
    parser.add_argument("email", metavar="EMAIL", type=str, help="email file to check")
    parser.add_argument("log", metavar="LOG", type=str, help="file for log output")

    args = parser.parse_args()

    sys.exit(main(args))
