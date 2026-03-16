#!/usr/bin/env python3

import argparse, os, json, requests, getpass

# Disable selfsigned certs triggering alerts
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT="pwn2ex v0.1"

class AuthToken():
    def __init__(self, status: str, token: str, datas):
        self.status = status
        self.token = token
        self.datas = datas


def main():
    p = argparse.ArgumentParser(description="Convert JSON from Pwndoc API calls into a readable Excel file")
    p.add_argument("-f","--file", required=True, nargs=1, help="Destination to store Excel file")
    p.add_argument("target", help="Target Pwndoc server")
    args = p.parse_args()
    username = input("Username: ")
    password = getpass.getpass(prompt="Password: ")
    totp = getpass.getpass(prompt="TOTP Token (Leave empty if none): ")
    login = auth(args.target, username, password, totp)
    if login.status != "success":
        err(login.datas)
    print(login.token)


def auth(target: str, username: str, password: str, totp: str):
    creds = {
        "username": username,
        "password": password
    }
    if totp is not None:
        creds["totpToken"] = totp

    url = target.rstrip('/')+'/api/users/token'
    resp = requests.post(url, headers={
        "accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT
    },
    json=creds, verify=False)
    contents = json.loads(resp.content)
    status = contents.get("status")
    datas = contents.get("datas")
    if status == "success":
        token = contents.get("datas", {}).get("token")
    else:
        token = ""
    return AuthToken(status=status, token=token, datas=datas)


def err(msg: str):
    print(f"[-] ERROR: {msg}")
    exit(2)


if __name__ == "__main__":
    main()
