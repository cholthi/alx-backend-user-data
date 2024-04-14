#!/usr/bin/env python3
"""provides filter_datum function that  obfuscates sensitive data
in the logs
"""
import re
import os
from typing import List
import logging
import mysql.connector

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
    logger = logging.getLogger("user_data")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    redact_formatter = RedactingFormatter(PII_FIELDS)
    handler = logging.StreamHandler()
    handler.setFormatter(redact_formatter)
    logger.addHandler(handler)
    return logger


def get_db() -> mysql.connector.connection.MySQLConnection:
    """ Returns a handle to mysql database connection"""
    db_host = os.getenv("PERSONAL_DATA_DB_HOST", "localhost")
    db_name = os.getenv("PERSONAL_DATA_DB_NAME", "")
    db_user = os.getenv("PERSONAL_DATA_DB_USERNAME", "root")
    db_pwd = os.getenv("PERSONAL_DATA_DB_PASSWORD", "")
    connection = mysql.connector.connect(
        host=db_host,
        port=3306,
        user=db_user,
        password=db_pwd,
        database=db_name,
    )
    return connection


def main():
    """Log the information about user records in a table.
    """
    fields = "name,email,phone,ssn,password,ip,last_login,user_agent"
    columns = fields.split(',')
    query = "SELECT {} FROM users;".format(fields)
    info_logger = get_logger()
    connection = get_db()
    with connection.cursor() as cursor:
        cursor.execute(query)
        rows = cursor.fetchall()
        for row in rows:
            record = map(
                lambda x: '{}={}'.format(x[0], x[1]),
                zip(columns, row),
            )
            msg = '{};'.format('; '.join(list(record)))
            args = ("user_data", logging.INFO, None, None, msg, None, None)
            log_record = logging.LogRecord(*args)
            info_logger.handle(log_record)


class RedactingFormatter(logging.Formatter):
    """ Redacting Formatter class
        """

    REDACTION = "***"
    FORMAT = "[HOLBERTON] %(name)s %(levelname)s %(asctime)-15s: %(message)s"
    SEPARATOR = ";"
    FORMAT_FIELDS = ('name', 'levelname', 'asctime', 'message')

    def __init__(self, fields: List[str]):
        super(RedactingFormatter, self).__init__(self.FORMAT)
        self.fields = fields

    def format(self, record: logging.LogRecord) -> str:
        """ Formats log message"""
        msg = super(RedactingFormatter, self).format(record)
        out = filter_datum(self.fields, self.REDACTION, msg, self.SEPARATOR)
        return out
