#!/usr/bin/env python3
"""Session view"""
from os import getenv
from models.user import User
from flask import request, jsonify, abort
from api.v1.views import app_views


@app_views.route("/auth_session/login", methods=["POST"], strict_slashes=False)
def login() -> str:
    """Handle login and create session ID"""
    email = request.form.get("email")
    password = request.form.get("password")

    if not email:
        return jsonify({"error": "email missing"}), 400

    if not password:
        return jsonify({"error": "password missing"}), 400

    users = User.search(attributes={"email": email})
    if not users:
        return jsonify({"error": "no user found for this email"}), 404

    for user in users:
        if not user.is_valid_password(password):
            return jsonify({"error": "wrong password"}), 401

        from api.v1.app import auth

        session_id = auth.create_session(user.id)
        output = jsonify(user.to_json())
        output.set_cookie(getenv("SESSION_NAME"), session_id)
        return output


@app_views.route(
    "/auth_session/logout", methods=["DELETE"], strict_slashes=False
)
def logout() -> str:
    """Handle logout and destroy user session"""
    from api.v1.app import auth

    if not auth.destroy_session(request):
        abort(404)
        return False
    return jsonify({}), 200
