#!/usr/bin/env python3
""" Basic authentication strategy"""
from api.v1.auth.auth import Auth


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

