"""A deliberately insecure mini web app so you can see ajar find web bugs.

Run:  ajar scan examples/vulnerable_webapp.py

Every handler below shows a common web vulnerability. ajar only points at the
risk and the safe fix — nothing here is exploited.
"""

import os
import pickle
import subprocess

import requests
import yaml
from flask import Flask, redirect, request

app = Flask(__name__)


@app.route("/user")
def get_user():
    uid = request.args.get("id")
    # SQL injection: user input spliced into the query.
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")  # noqa: F821
    return "ok"


@app.route("/ping")
def ping():
    host = request.args.get("host")
    # Command injection: user input into a shell command.
    os.system("ping -c 1 " + host)
    return "pong"


@app.route("/fetch")
def fetch():
    # SSRF: server fetches a URL the user controls.
    return requests.get(request.args.get("url")).text


@app.route("/read")
def read_file():
    # Path traversal: file path from user input.
    return open(request.args.get("path")).read()


@app.route("/go")
def go():
    # Open redirect: destination taken from the request.
    return redirect(request.args.get("next"))


@app.route("/load", methods=["POST"])
def load():
    # Insecure deserialization: pickle on request data == RCE.
    data = pickle.loads(request.data)
    config = yaml.load(request.data)  # unsafe loader
    return "loaded"


def run_task(cmd):
    # shell=True with external input.
    subprocess.run(cmd, shell=True)
