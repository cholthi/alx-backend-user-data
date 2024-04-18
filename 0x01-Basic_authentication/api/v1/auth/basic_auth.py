#!/usr/bin/env python3
""" Basic authentication strategy"""
from api.v1.auth.auth import Auth
import base64
import binascii
from models.user import User
from typing import TypeVar


class BasicAuth(Auth):
    """ Basic authentication adapter"""
    def extract_base64_authorization_header(
            self, authorization_header: str) -> str:
        """ Extracts basic authorization header value with Basic"""
        if not authorization_header or type(authorization_header) != str:
            return None
        if not authorization_header.startswith('Basic '):
            return None
        return authorization_header.split(' ')[1]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str) -> str:
        """ Decodes Authorization header value"""
        if not base64_authorization_header or type(
                base64_authorization_header) != str:
            return None
        try:
            decoded = base64.b64decode(base64_authorization_header)
            return decoded.decode('utf-8')
        except binascii.Error:
            None

    def extract_user_credentials(
            self,
            decoded_base64_authorization_header: str) -> (str, str):
        """ Extracts user login information from decoded base64 header"""
        if not decoded_base64_authorization_header or type(
                decoded_base64_authorization_header) != str:
            return (None, None)
        if ':' not in decoded_base64_authorization_header:
            return (None, None)
        return tuple(decoded_base64_authorization_header.split(':', 1)[:2])

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """ Load user from base64 crendentials"""
        if user_email is None or type(user_email) != str:
            return None
        if user_pwd is None or type(user_pwd) != str:
            return None
        try:
            if User.count() > 0:
                users = User.search({"email": user_email})
                if len(users) > 0:
                    user = users[0]
                    if not user.is_valid_password(user_pwd):
                        return None
                    return user
        except KeyError:
            return None
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Retreives the authenticated user from the request"""
        auth_header = extract_base64_authorization_header(
                self.authorization_header(request))
        user_email, password = extract_user_credentials(
                decode_base64_authorization_header(auth_header))
        return user_object_from_credentials(user_mail, password)
