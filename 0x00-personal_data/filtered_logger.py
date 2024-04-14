#!/usr/bin/env python3
"""provides filter_datum function that  obfuscates sensitive data
in the logs
"""
import re
import os
from typing import List
import logging

PII_FIELDS = ("name", "email", "phone", "ssn", "password")


def redact(redaction):
    """replacer function for re.sub"""
    return r'\g<field>={}'.format(redaction)


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """filter out sensitive data in the message"""
    pattern = r'(?P<field>{})=[^{}]*'.format(
                '|'.join(fields), separator)
    return re.sub(pattern, redact(redaction), message)


def get_logger() -> logging.Logger:
    """ returns a named logger that redacts PII data"""
    logger = logging.getlogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    redact_formatter = RedactingFormatter(PII_FIELDS)
    handler = logging.StreamHandler()
    handler.setFormatter(redact_formatter)
    logger.addHandler(handler)
    return logger


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Formats log message"""
        msg = super(RedactingFormatter, self).format(record)
        out = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return out
