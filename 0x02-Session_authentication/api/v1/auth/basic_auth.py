#!/usr/bin/env python3
"""
An implementation of basic authentication
"""
import base64
from typing import TypeVar
from models.user import User
from api.v1.auth.auth import Auth


class BasicAuth(Auth):
    """Class BasicAuth"""

    def extract_base64_authorization_header(
        self, authorization_header: str
    ) -> str:
        """
        Extract the Base64 part of the Authorization header for a Basic
        Authentication
        """
        if (
            authorization_header is None
            or not isinstance(authorization_header, str)
            or not authorization_header.startswith("Basic ")
        ):
            return None

        return authorization_header.split(" ")[-1]

    def decode_base64_authorization_header(
        self, base64_authorization_header: str
    ) -> str:
        """
        Decodes the Base64 string `base64_authorization_header`
        """
        if base64_authorization_header is None or not isinstance(
            base64_authorization_header, str
        ):
            return None

        try:
            decoded_bytes = base64.b64decode(base64_authorization_header)
            decoded_str = decoded_bytes.decode("utf-8")
        except ValueError:
            return None

        return decoded_str

    def extract_user_credentials(
        self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """
        Extract user email and password from the Base64 decoded value.
        """
        if (
            decoded_base64_authorization_header is None
            or not isinstance(decoded_base64_authorization_header, str)
            or decoded_base64_authorization_header.find(":") == -1
        ):
            return None, None
        email = decoded_base64_authorization_header.split(":")[0]
        password = decoded_base64_authorization_header.split(":")[-1]
        return email, password

    def user_object_from_credentials(
        self, user_email: str, user_pwd: str
    ) -> TypeVar("User"):
        """
        Create User instance based on user email and password
        """
        if (
            user_email is None
            or user_pwd is None
            or not isinstance(user_email, str)
            or not isinstance(user_pwd, str)
        ):
            return None

        try:
            users = User.search({"email": user_email})
        except Exception:
            return None

        for user in users:
            if user.is_valid_password(user_pwd):
                return user

        return None

    def current_user(self, request=None) -> TypeVar("User"):
        """Retrieves User instance from a request"""
        authorization_header = super().authorization_header(request)
        base64_auth_header = self.extract_base64_authorization_header(
            authorization_header
        )
        decode_auth_header = self.decode_base64_authorization_header(
            base64_auth_header
        )
        user_email, user_pwd = self.extract_user_credentials(
            decode_auth_header
        )
        user = self.user_object_from_credentials(user_email, user_pwd)
        return user
