#!/usr/bin/env python3
"""Auth helper
"""
import bcrypt
from typing import TypeVar
from sqlalchemy.orm.exc import NoResultFound
from db import DB


def _hash_password(password: str) -> bytes:
    """ returns bytes is a salted hash of the input password
    """
    salt = bcrypt.gensalt(rounds=15)
    return bcrypt.hashpw(password.encode(), salt)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()

    def register_user(self, email: str, password: str) -> TypeVar('User'):
        """ Register a user to the user store
        """
        try:
            _ = self._db.find_user_by(email=email)
            raise ValueError('User {} already exists'.format(email))
        except NoResultFound:
            user = self._db.add_user(email, _hash_password(
                password).decode('utf-8'))
        return user

    def valid_login(self, email: str, password: str) -> bool:
        """ checks for valid user crendentials in db
        """
        try:
            user = self._db.find_user_by(email=email)
            if bcrypt.checkpw(password.encode('utf-8'), user.hashed_password.encode('utf-8')):
                return True
            else:
                return False
        except NoResultFound:
            return False
