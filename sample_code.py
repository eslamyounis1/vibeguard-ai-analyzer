import pickle
import subprocess
import random

# VG003 - Hardcoded secrets
password = "super_secret_123"
api_key = "sk-abc987xyz"

def login(username, user_input):
    # VG001 - eval
    result = eval(user_input)

    # VG002 - exec
    exec("import os; os.getcwd()")

    # VG005 - subprocess with shell=True
    subprocess.run(user_input, shell=True)

    # VG004 - insecure randomness
    token = random.randint(0, 999999)

    # VG006 - pickle deserialization
    with open("data.pkl", "rb") as f:
        data = pickle.load(f)

    return result, token, data

def check_access(user):
    # VG007 - assert for security
    assert user.is_authenticated, "User must be logged in"
    assert user.has_permission("admin"), "Admin required"
