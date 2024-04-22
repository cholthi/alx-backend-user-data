#!/usr/bin/env python3
""" Session athentication adapter"""
from api.v1.auth.auth import Auth
from typing import Dict, TypeVar
import uuid
from models.user import User


class SessionAuth(Auth):
    """ session authentication adapter"""
    user_id_by_session_id: Dict = {}

    def create_session(self, user_id: str = None) -> str:
        """ Creates session ids for logged in users """
        if user_id is None or type(user_id) != str:
            return None
        sess_id = str(uuid.uuid4())
        SessionAuth.user_id_by_session_id[sess_id] = user_id
        return sess_id

    def user_id_for_session_id(self, session_id: str = None) -> str:
        """ Returns user id given a session ID string"""
        if session_id is None or type(session_id) != str:
            return None
        return self.user_id_by_session_id.get(session_id)

    def current_user(self, request=None) -> TypeVar('User'):
        """ Return the current user based on session cookie"""
        user_id = user_id_for_session_id(self.session_cookie(request))
        return User.get(user_id)
