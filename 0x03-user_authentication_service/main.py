#!/usr/bin/env python3
"""the advanced file"""
from requests import Session, Response


def register_user(email: str, password: str) -> None:
    """Registers a new user."""
    response = Session().post(
        'http://localhost:5000/users',
        data={'email': email, 'password': password},
    )
    assert response.status_code == 200
    assert response.json() == {
        'email': email,
        'message': 'user created'
    }


def log_in_wrong_password(email: str, password: str) -> None:
    """Attempts to log in with wrong password."""
    response = Session().post(
        'http://localhost:5000/sessions',
        data={'email': email, 'password': 'wrong_password'},
    )
    assert response.status_code == 401


def log_in(email: str, password: str) -> str:
    """Logs in with valid credentials."""
    response = Session().post(
        'http://localhost:5000/sessions',
        data={'email': email, 'password': password},
    )
    assert response.status_code == 200
    return response.cookies.get('session_id')


def profile_unlogged() -> None:
    """Attempts to access profile without being logged in."""
    response = Session().get('http://localhost:5000/profile')
    assert response.status_code == 403


def profile_logged(session_id: str) -> None:
    """Accesses the profile when logged in."""
    response = Session().get(
        'http://localhost:5000/profile',
        cookies={'session_id': session_id},
    )
    assert response.status_code == 200


def log_out(session_id: str) -> None:
    """Logs out from the current session."""
    response = Session().delete(
        'http://localhost:5000/sessions',
        cookies={'session_id': session_id},
    )
    assert response.status_code == 200


def reset_password_token(email: str) -> str:
    """Requests a password reset token."""
    response = Session().post(
        'http://localhost:5000/reset_password',
        data={'email': email},
    )
    assert response.status_code == 200
    return response.json().get('reset_token')


def update_password(email: str, reset_token: str, new_password: str) -> None:
    """Updates the user's password."""
    response = Session().put(
        'http://localhost:5000/reset_password',
        data={
            'email': email,
            'reset_token': reset_token,
            'new_password': new_password,
        },
    )
    assert response.status_code == 200


EMAIL = "guillaume@holberton.io"
PASSWD = "b4l0u"
NEW_PASSWD = "t4rt1fl3tt3"


if __name__ == "__main__":

    register_user(EMAIL, PASSWD)
    log_in_wrong_password(EMAIL, NEW_PASSWD)
    profile_unlogged()
    session_id = log_in(EMAIL, PASSWD)
    profile_logged(session_id)
    log_out(session_id)
    reset_token = reset_password_token(EMAIL)
    update_password(EMAIL, reset_token, NEW_PASSWD)
    log_in(EMAIL, NEW_PASSWD)
