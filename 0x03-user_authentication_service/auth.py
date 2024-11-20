#!/usr/bin/env python3
"""
Main file
"""
import bcrypt
import uuid
from db import DB
from user import User
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """hashes the password"""
    byte = password.encode('utf-8')
    salt = bcrypt.gensalt()
    return bcrypt.hashpw(byte, salt)


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        self._db = DB()
    
    def register_user(self, email: str, password: str) -> User:
        """Registers a User"""
        user = self._db._session.query(User).filter_by(email=email).first()
        if user:
            raise ValueError(f"User {email} already exists")
        else:
            hashed_password = _hash_password(password)
            user = self._db.add_user(email, hashed_password)
            self._db._session.add(user)
            self._db._session.commit()
            return user

    def valid_login(self, email: str, password: str) -> bool:
        """validates if the user exists and id the passwd is correct"""
        if email is None or password is None:
            return False
        user = self._db._session.query(User).filter_by(email=email).first()
        if user is None:
            return False
        hashed = user.hashed_password
        if bcrypt.checkpw(password.encode('utf-8'), hashed):
            return True
        else:
            return False

    def _generate_uuid(self) -> str:
        """generate id using uuid"""
        return str(uuid.uuid4())

    def create_session(self, email: str) -> str:
        """generates a session_id if user exists"""
        if email is None:
            return None
        user = self._db._session.query(User).filter_by(email=email).first()
        if user is None:
            return None
        id = self._generate_uuid()
        user.session_id = id
        self._db._session.commit()
        return id
