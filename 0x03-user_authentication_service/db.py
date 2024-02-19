#!/usr/bin/env python3
"""DB module
"""
from typing import Union
from sqlalchemy import create_engine
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker
from sqlalchemy.orm.session import Session
from sqlalchemy.exc import InvalidRequestError
from sqlalchemy.orm.exc import NoResultFound

from user import Base, User


class DB:
    """DB class
    """
    def __init__(self) -> None:
        """Initialize a new DB instance
        """
        self._engine = create_engine(
            "sqlite:///a.db",
            echo=False
        )
        Base.metadata.drop_all(self._engine)
        Base.metadata.create_all(self._engine)
        self.__session = None

    @property
    def _session(self) -> Session:
        """Memoized session object
        """
        if self.__session is None:
            DBSession = sessionmaker(bind=self._engine)
            self.__session = DBSession()
        return self.__session

    def add_user(self, email: str, hashed_password: str) -> User:
        """
        method to add user to database

        Args:
            email (str): _description_
            hashed_password (str): _description_

        Returns:
            User: _description_
        """
        added_user = User(email=email, hashed_password=hashed_password)

        self._session.add(added_user)
        self._session.commit()

        return added_user

    def find_user_by(
        self,
        **kwargs
    ) -> Union[User, InvalidRequestError, NoResultFound]:
        """
        find user by attribute

        Raises:
            InvalidRequestError: _description_
            NoResultFound: _description_

        Returns:
            Union[User, InvalidRequestError, NoResultFound]: _description_
        """
        all_users = self._session.query(User).all()
        user_keys = User.__dict__.keys()

        for k, v in kwargs.items():
            if k not in user_keys:
                raise InvalidRequestError
            else:
                for user in all_users:
                    if getattr(user, k) == v:
                        return user

        raise NoResultFound

    def update_user(self, user_id: int, **kwargs) -> None:
        """
        update user by id

        Args:
            user_id (int): _description_
        """
        try:
            user = self.find_user_by(id=user_id)
        except NoResultFound:
            raise ValueError

        for k, v in kwargs.items():
            if k not in User.__dict__:
                raise ValueError
            setattr(user, k, v)

        self._session.commit()
