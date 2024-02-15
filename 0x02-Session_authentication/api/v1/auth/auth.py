#!/usr/bin/env python3
"""
Auth class
"""
from os import getenv
from flask import Flask, request
from typing import TypeVar, List


class Auth:
    """Auth class to manage the API authentication"""

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """Require auth"""
        if path is None or excluded_paths is None or len(excluded_paths) == 0:
            return True

        if not path.endswith("/"):
            path += "/"

        if path in excluded_paths:
            return False

        return True

    def authorization_header(self, request=None) -> str:
        """Authorization header"""
        if request is None:
            return None

        return request.headers.get("Authorization")

    def current_user(self, request=None) -> TypeVar("User"):
        """Current user"""
        return None

    def session_cookie(self, request=None) -> str:
        """Retrieves cookie value from request"""
        if request is None:
            return None
        return request.cookies.get(getenv("SESSION_NAME"))
