#!/usr/bin/env python3
""" Provide Auth base class for user authenitcation strategies"""
from flask import request
from typing import List, TypeVar
import re


class Auth:
    """ Base class for authentication strategies"""
    def require_auth(self, path: str,
                     excluded_paths: List[str]) -> bool:
        """ check path if auth is required"""
        if path is None:
            return True
        if not excluded_paths:
            return True
        normalized_path = path + '/' if not path.endswith(
                        '/') else path
        for excluded_path in excluded_paths:
            if excluded_path.endswith('*'):
                pattern = fr'{excluded_path[:-1]}.*'
                if re.match(pattern, normalized_path):
                    return False
            if excluded_path == normalized_path:
                return False
        return True

    def authorization_header(self, request=None) -> str:
        """Checks for authorization header and return it"""
        if request is None:
            return None
        if request.headers.get('Authorization'):
            return request.headers.get('Authorization')
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ Returns the authenticated user from the request"""
        return None
