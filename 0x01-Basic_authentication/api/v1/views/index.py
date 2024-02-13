#!/usr/bin/env python3
""" Module of Index views
"""
from flask import jsonify, abort
from api.v1.views import app_views
from models.user import User


@app_views.route('/status', methods=['GET'], strict_slashes=False)
def status() -> str:
    """ GET /api/v1/status
    Return:
      - the status of the API
    """
    return jsonify({"status": "OK"})


@app_views.route('/stats/', strict_slashes=False)
def stats() -> str:
    """ GET /api/v1/stats
    Return:
      - the number of each objects
    """
    stats2 = {}
    stats2['users'] = User.count()
    return jsonify(stats2)


@app_views.route('/unauthorized/', strict_slashes=False)
def unauthorized() -> str:
    """ GET /api/v1/unauthorized
    Return:
      - abort(401)
    """
    abort(401)


@app_views.route('/forbidden/', strict_slashes=False)
def forbidden() -> str:
    """ GET /api/v1/forbidden
    Return:
      - abort(403)
    """
    abort(403)
