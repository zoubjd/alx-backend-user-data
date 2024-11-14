#!/usr/bin/env python3
"""Authentication class for managing access control in API requests."""

from flask import request
from typing import List, TypeVar


class Auth:
    """Class to manage the authorization requirements for API routes."""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Determine if a path requires authentication.

        Args:
            path (str): The path to check.
            excluded_paths (List[str]): A list of
            paths that do not require authentication.

        Returns:
            bool: True if authentication is required, False otherwise.
        """
        if path is None:
            return True
        if excluded_paths is None or len(excluded_paths) == 0:
            return True

        if not path.endswith('/'):
            path = path + '/'
        for paf in excluded_paths:
            if paf.endswith('*'):
                if path.startswith(paf[:-1]):
                    return False
        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """Retrieve the authorization header from the request.

        Args:
            request: The Flask request object.

        Returns:
            str: The value of the authorization header if present,
            None otherwise.
        """
        if request is None:
            return None
        if 'Authorization' in request.headers:
            return request.headers['Authorization']
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """Retrieve the current user associated with the request.

        Args:
            request: The Flask request object.

        Returns:
            User: The current user, if available.
        """
        return None
