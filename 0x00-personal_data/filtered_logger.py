#!/usr/bin/env python3
"""provides filter_datum function that  obfuscates sensitive data
in the logs
"""
import re
from typing import List


def redact(redaction):
    """replacer function for re.sub"""
    return r'\g<field>={}'.format(redaction)


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """filter out sensitive data in the message"""
    pattern = r'(?P<field>{})=[^{}]*'.format(
                '|'.join(fields), separator)
    return re.sub(pattern, redact(redaction), message)
