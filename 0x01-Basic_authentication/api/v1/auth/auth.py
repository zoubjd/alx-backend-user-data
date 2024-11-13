#!/usr/bin/env python3
"""auth class"""
from flask import request
from typing import List, TypeVar


class Auth:
    """Auth class"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """require auth"""
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        if not path.endswith('/'):
            path = path + '/'
        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """authorization header"""
        if request in None:
            return None
        if 'Authorization' in request.headers:
            return request.headers['Authorization']
        else:
            return None
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """current user"""
        return None
