#!/usr/bin/env python3
"""
Main file
"""
from flask import Flask, jsonify, request, redirect, abort, make_response
from auth import Auth


AUTH = Auth()

app = Flask(__name__)


@app.route('/', methods=['GET'], strict_slashes=False)
def hello():
    """the main route"""
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'], strict_slashes=False)
def register():
    """the register route"""
    email = request.form.get('email')
    password = request.form.get('password')
    try:
        user = AUTH.register_user(email, password)
        return jsonify({"email": email, "message": "user created"})
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'], strict_slashes=False)
def login():
    """basically logs in the user if it exist
    and if the email and pwd are correct"""
    email = request.form.get('email')
    password = request.form.get('password')
    if email is None or password is None:
        abort(401)
    if AUTH.valid_login(email, password):
        session_id = AUTH.create_session(email)
        response = make_response(jsonify({"email": email,
                                          "message": "logged in"}))
        response.set_cookie("session_id", session_id)
        return response
    else:
        abort(401)


@app.route('/sessions', methods=['DELETE'], strict_slashes=False)
def logout():
    """the logout route"""
    session_id = request.cookies.get('session_id')
    if session_id is None:
        return jsonify({"message": "No session id found"}), 403
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        return jsonify({"message": "No User found"}), 403
    AUTH.destroy_session(user.id)
    return redirect("/")


@app.route('/profile', methods=['GET'], strict_slashes=False)
def profile():
    """user profile's link"""
    session_id = request.cookies.get('session_id')
    if session_id is None:
        return jsonify({"message": "No session id found"}), 403
    user = AUTH.get_user_from_session_id(session_id)
    if user is None:
        return jsonify({"message": "No User found"}), 403
    return jsonify({"email": user.email}), 200


@app.route('/reset_password', methods=['POST'], strict_slashes=False)
def get_reset_password_token():
    """the way for the user to reset his password"""
    email = request.form.get('email')
    if email is None:
        abort(403)
    user = AUTH._db.find_user_by(email=email)
    if user is None:
        return jsonify({"message": "No user found with email"}), 403
    token = AUTH.get_reset_password_token(email)
    return jsonify({"email": email, "reset_token": token}), 200


@app.route('/reset_password', methods=['PUT'], strict_slashes=False)
def update_password():
    """updates the forgotten pwd"""
    email = request.form.get("email")
    tocken = request.form.get("reset_token")
    pwd = request.form.get("new_password")
    try:
        AUTH.update_password(tocken, pwd)
        return jsonify({"email": email, "message": "Password updated"}), 200
    except ValueError:
        return jsonify({"message": "Data entered not valid"}), 403


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
