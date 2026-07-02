"""A deliberately insecure example so you can see ajar in action.

Run:  ajar scan examples/vulnerable_config.py

Every line below is a teaching example of a door left open by default.
Nothing here is exploited — ajar only points at the risk and the fix.
"""

import os

import requests

# --- fail-open: the flagship problem ------------------------------------
# If APP_ENV is unset or misspelled, auth silently turns OFF.
if os.getenv("APP_ENV") != "production":
    require_auth = False

# Security relaxed by matching an env string — any typo takes the open path.
if os.environ.get("STAGE") == "dev":
    ssl_verify = False


def is_authorized(user, resource):
    try:
        return check_permission(user, resource)  # noqa: F821
    except Exception:
        # Fail-open: a downstream error becomes a free pass.
        return True


# --- insecure defaults ---------------------------------------------------
DEBUG = True
requests.get("https://internal.example.com/data", verify=False)
HOST = "0.0.0.0"

# --- hardcoded secrets ---------------------------------------------------
API_KEY = "sk_live_super_secret_value_1234"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"
