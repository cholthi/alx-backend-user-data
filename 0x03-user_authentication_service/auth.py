#!/usr/bin/env python3
"""Auth helper
"""
import bcrypt


def _hash_password(password: str) -> bytes:
    """ returns bytes is a salted hash of the input password
    """
    salt = bcrypt.gensalt(rounds=15)
    return bcrypt.hashpw(password.encode(), salt)
