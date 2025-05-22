#!/usr/bin/env python3
import random
import requests
from bs4 import BeautifulSoup
import sys
import re

# Check args
if len(sys.argv) < 2:
    print("Usage: python3 injectscan.py <url_file> [cookie_string]")
    sys.exit(1)

url_file = sys.argv[1]
cookie = sys.argv[2] if len(sys.argv) > 2 else None
ua_file = "/usr/share/sqlmap/data/txt/user-agents.txt"
output_file = "reflected_output.txt"

# Load user-agents from sqlmap's list
with open(ua_file, 'r') as f:
    user_agents = [line.strip() for line in f if line.strip()]

# Setup headers with random SQLMap UA
def get_headers():
    headers = {"User-Agent": random.choice(user_agents)}
    if cookie:
        headers["Cookie"] = cookie
    return headers

# Read and filter URLs
with open(url_file, 'r') as f:
    urls = [line.strip() for line in f if not re.search(r'\.(css|png|jpg|jpeg|svg|gif|wolf)', line.strip(), re.IGNORECASE)]

# Clear previous output
with open(output_file, "w") as f:
    f.write("")

# Begin scanning
for url in urls:
    print(f"\033[1;34m[+] Scanning: {url}\033[0m")
    try:
        r = requests.get(url, headers=get_headers(), timeout=10)
        js_vars = re.findall(r'\b(?:var|let|const)\s+([a-zA-Z_][a-zA-Z0-9_]*)', r.text)
        js_vars = list(set(js_vars))  # de-duplicate

        for var in js_vars:
            base = url.split('?')[0]
            test_url = f"{base}?{var}=msec"
            r2 = requests.get(test_url, headers=get_headers(), timeout=10)

            if "msec" in r2.text:
                inj_url = f"{base}?{var}=<i>msec"
                r3 = requests.get(inj_url, headers=get_headers(), timeout=10)
                soup = BeautifulSoup(r3.text, "html.parser")

                if "<i>msec" in r3.text:
                    print(f"\033[1;91m[VULNERABLE: RAW HTML INJECTION]\033[0m {inj_url}")
                    with open(output_file, "a") as f:
                        f.write(f"[VULNERABLE] {inj_url}\n")
                    tag = soup.find(string=re.compile(r"<i>msec"))
                    if tag:
                        print(f"\033[1;90m--- Reflection Context ---\033[0m")
                        print(tag.strip())

                elif "&lt;i&gt;msec" in r3.text:
                    print(f"\033[1;93m[ENCODED REFLECTION]\033[0m {inj_url}")
                    with open(output_file, "a") as f:
                        f.write(f"[ENCODED] {inj_url}\n")
                    tag = soup.find(string=re.compile(r"&lt;i&gt;msec"))
                    if tag:
                        print(f"\033[1;90m--- Encoded Context ---\033[0m")
                        print(tag.strip())

                else:
                    print(f"\033[1;33m[REFLECTED BUT NOT IN HTML CONTEXT]\033[0m {test_url}")
                    with open(output_file, "a") as f:
                        f.write(f"[REFLECTED-BUT-UNSURE] {test_url}\n")
            else:
                print(f"\033[0;37m[-] Not Reflected:\033[0m {test_url}")
    except requests.RequestException as e:
        print(f"\033[1;31m[ERROR]\033[0m {url} => {e}")
