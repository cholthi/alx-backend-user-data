#!/usr/bin/env python3
"""Auth helper
"""
import bcrypt
from typing import TypeVar, Union
from sqlalchemy.orm.exc import NoResultFound
from db import DB
import uuid


def _hash_password(password: str) -> bytes:
    """ returns bytes is a salted hash of the input password
    """
    salt = bcrypt.gensalt(rounds=15)
    return bcrypt.hashpw(password.encode(), salt)


def _generate_uuid() -> str:
    """ generate a uuid string
    """
    return str(uuid.uuid4())


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
            if bcrypt.checkpw(
                    password.encode(
                        'utf-8'), user.hashed_password.encode('utf-8')):
                return True
            else:
                return False
        except NoResultFound:
            return False

    def create_session(self, email: str) -> Union[str, None]:
        """ Create a user session and return the
        session identifier
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            self._db.update_user(user.id, session_id=session_id)
            return session_id
        except NoResultFound:
            return None
