#!/usr/bin/env python3
"""provides filter_datum function that  obfuscates sensitive data
in the logs
"""
import re
from typing import List


def redact(match, redaction):
    """replacer function for re.sub"""
    m = match.group(1)
    return f'{m}={redaction}'


def filter_datum(fields: List[str], redaction: str,
                 message: str, separator: str) -> str:
    """filter out sensitive data in the message"""
    for field in fields:
        pattern = r'({})=[^{}]+'.format(re.escape(field), separator)
        msg = re.sub(pattern, lambda m: redact(m, redaction), message)
    return msg
