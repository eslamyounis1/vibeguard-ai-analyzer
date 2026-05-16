"""
Deliberately vulnerable sample for testing VibeGuard security rules.

Do not copy these patterns into real applications.
"""

import cPickle
import hashlib
import os
import pickle
import random
import subprocess

import requests
import yaml
from pickle import loads
from random import choice
from requests import post
from subprocess import run
from yaml import load


API_KEY = "sk-test-hardcoded-secret-123456"
password = "admin123"
auth_token = "tok_live_example_987654"


def vg001_eval(user_expression):
    return eval(user_expression)


def vg002_exec(user_code):
    exec(user_code)


def vg003_hardcoded_secret():
    private_key = "-----BEGIN PRIVATE KEY-----fake-----END PRIVATE KEY-----"
    return private_key


def vg004_insecure_random():
    token_part = random.randint(100000, 999999)
    fallback = choice(["alpha", "beta", "gamma"])
    return f"{token_part}-{fallback}"


def vg005_subprocess_shell_true(filename):
    subprocess.run(f"cat {filename}", shell=True)
    run(f"ls {filename}", shell=True)


def vg006_pickle_deserialization(raw, file_obj):
    one = pickle.loads(raw)
    two = pickle.load(file_obj)
    three = cPickle.loads(raw)
    four = loads(raw)
    return one, two, three, four


def vg007_assert_validation(user):
    assert user.is_authenticated
    assert user.has_permission("admin")
    return True


def vg008_weak_hash(password_value):
    md5_hash = hashlib.md5(password_value.encode()).hexdigest()
    sha1_hash = hashlib.sha1(password_value.encode()).hexdigest()
    return md5_hash, sha1_hash


def vg009_os_shell_execution(path):
    os.system(f"rm -rf {path}")
    os.popen(f"cat {path}").read()


def vg010_unsafe_yaml_load(raw_yaml):
    config_a = yaml.load(raw_yaml)
    config_b = load(raw_yaml)
    return config_a, config_b


def vg011_tls_verification_disabled():
    profile = requests.get("https://example.com/profile", verify=False)
    created = post("https://example.com/users", json={"name": "demo"}, verify=False)
    return profile.status_code, created.status_code


def vg012_debug_mode_enabled(app):
    app.run(debug=True)


def vg013_sql_query_construction(cursor, username, user_id):
    cursor.execute(f"SELECT * FROM users WHERE username = '{username}'")
    cursor.execute("SELECT * FROM users WHERE id = %s" % user_id)
    cursor.execute("DELETE FROM users WHERE username = '{}'".format(username))
    cursor.execute("UPDATE users SET active = 0 WHERE id = " + str(user_id))


def ignored_example(cursor, query):
    # vibeguard: ignore sql_query_construction
    cursor.execute(query)
