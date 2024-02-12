#!/usr/bin/env python3
""" Basic auth """
import base64
from typing import TypeVar
from api.v1.auth.auth import Auth
from models.user import User


class BasicAuth(Auth):
    """ BasicAuth class
    """
    def extract_base64_authorization_header(self,
                                            authorization_header: str) -> str:
        """ extract_base64_authorization_header
        """
        if authorization_header is None or \
                not isinstance(authorization_header, str) or \
                not authorization_header.startswith("Basic "):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(self,
                                           base64_authorization_header: str
                                           ) -> str:
        """ decode_base64_authorization_header
        """
        if base64_authorization_header is None or \
                not isinstance(base64_authorization_header, str):
            return None
        try:
            decoded_str = base64.b64decode(base64_authorization_header)
            return decoded_str.decode('utf-8')
        except Exception:
            return None

    def extract_user_credentials(self,
                                 decoded_base64_authorization_header: str
                                 ) -> (str, str):
        """ extract_user_credentials
        """
        if decoded_base64_authorization_header is None or \
                not isinstance(decoded_base64_authorization_header, str) or \
                ':' not in decoded_base64_authorization_header:
            return (None, None)
        decoded_credentials = decoded_base64_authorization_header.split(':', 1)
        if len(decoded_credentials) < 2:
            return (None, None)
        return tuple(decoded_credentials)

    def user_object_from_credentials(self,
                                     user_email: str,
                                     user_pwd: str) -> TypeVar('User'):
        """ user_object_from_credentials
        """
        if user_email is None or not isinstance(user_email, str) or \
                user_pwd is None or not isinstance(user_pwd, str):
            return None
        users = User.search({'email': user_email})
        if not users:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
        return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ current_user
        """
        header = self.authorization_header(request)
        base64_header = self.extract_base64_authorization_header(header)
        decoded_header = self.decode_base64_authorization_header(base64_header)
        user_credentials = self.extract_user_credentials(decoded_header)
        return self.user_object_from_credentials(user_credentials[0],
                                                 user_credentials[1])
