#!/usr/bin/env python3
""" APP
"""
from flask import Flask, jsonify, request
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


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
