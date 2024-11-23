#!/usr/bin/env python3
""""returns the log message obfuscated"""
import logging
import typing
import re


def filter_datum(
    fields: typing.List[str], redaction: str,
        message: str, separator: str) -> str:
    """returns the log message obfuscated"""
    for field in fields:
        message = re.sub(
            f'{field}=.*?{separator}',
            f'{field}={redaction}{separator}', message)
    return message
