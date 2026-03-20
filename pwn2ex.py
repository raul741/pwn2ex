#!/usr/bin/env python3

import argparse, json, requests, getpass, shutil
from openpyxl import Workbook, load_workbook

# Disable selfsigned certs triggering alerts
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

USER_AGENT="pwn2ex v0.1"

class PwnResponse():
    def __init__(self, status: str, datas):
        self.status = status
        self.datas = datas

class Vulnerability():
    def __init__(self, id: int, description: str, criticality: str, cvss: float, assets: list[str], detection_date: str, root_cause: str, corrective_action: str, close_date: str, evidence: str, active: str, observation: str):
        self.id = id
        self.description = description
        self.criticality = criticality
        self.cvss = cvss
        self.assets = assets
        self.detection_date = detection_date
        self.root_cause = root_cause
        self.corrective_action = corrective_action
        self.close_date = close_date
        self.evidence = evidence
        self.active = active
        self.observation = observation


class Audit():
    def __init__(self, id: str, title: str, auditType: str, findings: list[Vulnerability], company: str):
        self.id = id
        self.title = title
        self.auditType = auditType
        self.findings = findings
        self.company = company


def main():
    vulns = []
    vuln1 = Vulnerability(
        id=1,
        description="Cisco ASA Outdated Firmware: Remote Code Execution & Arbitrary File Read",
        criticality="Critical",
        cvss=9.0,
        assets=["50.220.195.3"],
        detection_date="21/01/2026",
        root_cause="Obsolete firmware version (Cisco ASA 5500) allows authentication bypass",
        corrective_action="Migrate to the latest Cisco Security Advisory version or Cisco Secure Firewall 3100 apply patches,restrict external access immediately",
        close_date="TBD",
        evidence="Version identified (85% confidence) and PwnResponseentication Bypass POC successful",
        active="Yes",
        observation="High probability of compromise; persistence mechanisms may survive patching"
    )
    vuln2 = Vulnerability(
        id=2,
        description="Internet Key Exchange",
        criticality="Medium",
        cvss=5.3,
        assets=["50.247.246.193", "66.152.110.218", "50.75.0.34", "50.212.67.17"],
        detection_date="21/01/2026",
        root_cause="VPN service uses IKEv1 Aggressive Mode transmitting hash before encryption",
        corrective_action="Disable Aggressive Mode (force Main Mode) or replace PSK with Digital Certificates",
        close_date="TBD",
        evidence="Captured Aggressive Mode Handshake (PSK hash)",
        active="Yes",
        observation="Dictionary attack failed on captured hashes, but protocol remains insecure"
    )
    vulns.append(vuln1)
    vulns.append(vuln2)

    audit = Audit(
        id="69bd30dba1444040f305e23b",
        title="cool audit",
        auditType="Hacking ético",
        findings=vulns,
        company="Tolovendo SL"
    )
    save_audit(audit=audit, template="/mnt/c/Users/RaúlBulgariuSuciu/Desktop/plantilla.xlsx", output="/mnt/c/Users/RaúlBulgariuSuciu/Desktop/OUTPUT.xlsx")




def save_audit(audit: Audit, template: str, output: str):
    ROW=4
    wb = load_workbook(template)
    log("Select the sheet to fill:")
    sheet = wb[list_choice(wb.sheetnames)]
    for i, vuln in enumerate(audit.findings):
        sheet[f"B{ROW}"].value = i+1
        sheet[f"C{ROW}"].value = vuln.description
        sheet[f"D{ROW}"].value = vuln.criticality
        sheet[f"E{ROW}"].value = vuln.cvss
        sheet[f"F{ROW}"].value = ", ".join(vuln.assets)
        sheet[f"G{ROW}"].value = vuln.detection_date
        sheet[f"H{ROW}"].value = vuln.root_cause
        sheet[f"I{ROW}"].value = vuln.corrective_action
        sheet[f"J{ROW}"].value = vuln.close_date
        sheet[f"K{ROW}"].value = vuln.evidence
        sheet[f"L{ROW}"].value = vuln.active
        sheet[f"M{ROW}"].value = vuln.observation
        ROW+=1
    wb.save(output)
    log(f"File \"{output}\" created successfully!")


def list_choice(array: list):
    for i, v in enumerate(array):
        print(f"[{i}] {v}")
    try:
        id_item = int(input("Choice (ID): "))
        item = array[id_item]
    except Exception as e:
        raise e
    return item


# def req(target: str, token: str):
#     resp = requests.get(target, headers={
#         "accept": "application/json",
#         "Content-Type": "application/json",
#         "User-Agent": USER_AGENT
#     },
#     cookies={'token': token}, verify=False)
#     contents = json.loads(resp.content)
#     status = contents.get("status")
#     datas = contents.get("datas")
#     return PwnResponse(status=status, datas=datas)
#

def auth(target: str, username: str, password: str, totp: str):
    url = target + "/api/users/token"
    creds = {
        "username": username,
        "password": password
    }
    if totp is not None:
        creds["totpToken"] = totp

    resp = requests.post(url, headers={
        "accept": "application/json",
        "Content-Type": "application/json",
        "User-Agent": USER_AGENT
    },
    json=creds, verify=False)
    contents = json.loads(resp.content)
    status = contents.get("status")
    datas = contents.get("datas")
    return check_success(PwnResponse(status=status, datas=datas))


def check_success(response: PwnResponse):
    if response.status != "success":
        err(response.datas)
    return response


def log(msg: str):
    print(f"[+] {msg}")


def err(msg: str):
    print(f"[-] ERROR: {msg}")
    exit(2)


if __name__ == "__main__":
    main()

    # ----------------------------------------------------
    # p = argparse.ArgumentParser(description="Convert JSON from Pwndoc API calls into a readable Excel file")
    # p.add_argument("-f","--file", required=True, nargs=1, help="Destination to store Excel file")
    # p.add_argument("target", help="Target Pwndoc server")
    # args = p.parse_args()
    #
    # username = input("Username: ")
    # password = getpass.getpass(prompt="Password: ")
    # totp = getpass.getpass(prompt="TOTP Token (Leave empty if none): ")
    # target = args.target.rstrip('/')
    #
    # login = auth(target, username, password, totp)
    # if login.status != "success":
    #     err(login.datas)
    # token = login.datas["token"]
    # print(token)
    # -------------------------------------------------------
