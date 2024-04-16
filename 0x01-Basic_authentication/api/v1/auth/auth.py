#!/usr/bin/env python3
""" Provide Auth base class for user authenitcation strategies"""
from flask import request
from typing import List, TypeVar


class Auth:
    """ Base class for authentication strategies"""
    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """ check path if auth is required"""
        if path is None:
            return True
        if not excluded_paths:
            return True
        normalized_path = path + '/' if not path.endswith(
                        '/') else path
        if normalized_path in excluded_paths:
            return False
        return True

    def authorization_header(self, request=None) -> str:
        if not request:
            return None
        if request.headers.get('Authorization'):
            return request.headers.get('Authorization')
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        return None
