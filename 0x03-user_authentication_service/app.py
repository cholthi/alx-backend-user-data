#!/usr/bin/env python3
""" APP
"""
from flask import Flask, jsonify, request, make_response, abort
from werkzeug.wrappers import Response
from auth import Auth

app = Flask(__name__)
app.url_map.strict_slashes = True
auth = Auth()


@app.route('/', methods=['GET'])
def index() -> Response:
    """ index view function
    """
    return jsonify({"message": "Bienvenue"})


@app.route('/users', methods=['POST'])
def users() -> Response:
    """ Users
    """
    user_data = request.form
    try:
        user = auth.register_user(
                user_data["email"], user_data["password"])
        if user:
            return jsonify({
                "email": user.email,
                "message": "user created"
                })
    except ValueError:
        return jsonify({"message": "email already registered"}), 400


@app.route('/sessions', methods=['POST'])
def login() -> Response:
    """ Login endpoint
    """
    email = request.form.get('email')
    password = request.form.get('password')
    if not auth.valid_login(email, password):
        return abort(401)
    session_id = auth.create_session(email)
    if session_id is None:
        return abort(401)
    body = {"email": email, "message": "logged in"}
    response = make_response(jsonify(body))
    response.set_cookie('session_id', session_id)
    return response


@app.route('/sessions', methods=['DELETE'])
def logout() -> Response:
    """Logout endpoint
    """
    session_id = request.cookies.get('session_id')
    user = auth.user_from session_id(session_id)
    if user is None:
        abort(403)
    auth.destroy_session(user.id)
    response = make_response()
    response.delete_cookie("session_id")
    return response


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
