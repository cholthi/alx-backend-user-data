#!/usr/bin/env python3
""" APP
"""
from flask import Flask, jsonify


app = Flask(__name__)
app.ur_map.strict_slashes = True


@app.route('/', methods=['GET'])
def index():
    """ index view function
    """
    return jsonify({"message": "Bienvenue"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port="5000")
