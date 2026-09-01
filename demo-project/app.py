import os
import subprocess
import sqlite3

# SQL Injection vulnerability
def get_user(user_id):
    query = f"SELECT * FROM users WHERE id = {user_id}"
    cursor.execute(query)

# Shell injection vulnerability
def run_command(user_input):
    subprocess.run(user_input, shell=True)

# Hardcoded secret
API_KEY = "sk-1234567890abcdef"

# Unsafe deserialization
import pickle
def load_model(path):
    return pickle.load(open(path, "rb"))

# Eval usage
def calculate(expression):
    return eval(expression)

# Bare except
def risky():
    try:
        x = 1 / 0
    except:
        pass
