import os
import re
import email
import requests
import time
from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse, quote

# === CONFIGURATION ===
VT_API_KEY = "5cdd731ffe102ac14c823178e67cddfddfdca2f92d65c489de9e8f276a19cc27"  # Replace with your VirusTotal API key
SAVE_DIR = "attachments"

# === HELPERS ===

def extract_attachments_and_urls(eml_path, save_dir=SAVE_DIR):
    with open(eml_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    if not os.path.exists(save_dir):
        os.makedirs(save_dir)

    attachments = []
    for part in msg.iter_attachments():
        filename = part.get_filename()
        if filename:
            file_path = os.path.join(save_dir, filename)
            with open(file_path, 'wb') as af:
                af.write(part.get_payload(decode=True))
            attachments.append(file_path)

    # Extract body and URLs
    body = ""
    if msg.is_multipart():
        for part in msg.walk():
            if part.get_content_type() == 'text/plain':
                body += part.get_content()
    else:
        body = msg.get_content()

    urls = re.findall(r'https?://[^\s<>\"]+', body)
    return attachments, urls

def scan_file_virustotal(file_path, api_key=VT_API_KEY):
    print(f"🔍 Scanning attachment with VirusTotal: {os.path.basename(file_path)}")
    upload_url = "https://www.virustotal.com/api/v3/files"
    headers = {"x-apikey": api_key}

    # Step 1: Submit file
    with open(file_path, "rb") as f:
        resp = requests.post(upload_url, headers=headers, files={"file": f})
    if resp.status_code != 200:
        return f"Error uploading file: {resp.status_code} {resp.text}"

    file_id = resp.json().get("data", {}).get("id")

    # Step 2: Wait and fetch report
    report_url = f"https://www.virustotal.com/api/v3/analyses/{file_id}"
    time.sleep(10)

    report_resp = requests.get(report_url, headers=headers)
    if report_resp.status_code != 200:
        return f"Error fetching file report: {report_resp.status_code} {report_resp.text}"

    stats = report_resp.json().get("data", {}).get("attributes", {}).get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    return f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}"

def scan_url_virustotal(url, api_key=VT_API_KEY):
    print(f"🔍 Submitting URL to VirusTotal: {url}")
    headers = {"x-apikey": api_key}
    scan_url = "https://www.virustotal.com/api/v3/urls"
    response = requests.post(scan_url, headers=headers, data={"url": url})
    if response.status_code != 200:
        return f"Error submitting URL: {response.status_code} {response.text}"

    url_id = response.json().get("data", {}).get("id")
    if not url_id:
        return "Error: No scan ID returned."

    # Fetch report
    report_url = f"https://www.virustotal.com/api/v3/analyses/{quote(url_id)}"
    time.sleep(10)
    report = requests.get(report_url, headers=headers)
    if report.status_code != 200:
        return f"Error fetching report: {report.status_code} {report.text}"

    data = report.json().get("data", {})
    stats = data.get("attributes", {}).get("stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)

    return f"Malicious: {malicious}, Suspicious: {suspicious}, Harmless: {harmless}"

def is_obfuscated_url(url):
    suspicious_shorteners = ['bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly']
    domain = urlparse(url).netloc
    return any(short in domain for short in suspicious_shorteners)

# === MAIN SCANNER FUNCTION ===

def scan_email(eml_path):
    print(f"\n📂 Scanning: {eml_path}")
    attachments, urls = extract_attachments_and_urls(eml_path)

    print("\n📎 Attachments found:")
    for file in attachments:
        result = scan_file_virustotal(file)
        print(f" - {file} → {result}")

    print("\n🔗 URLs found:")
    for url in urls:
        obf = "Yes" if is_obfuscated_url(url) else "No"
        vt_result = scan_url_virustotal(url)
        print(f"\n- {url}")
        print(f"  Obfuscated: {obf}")
        print(f"  VirusTotal: {vt_result}")

# === CLI ENTRY POINT ===

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python attachment_link_scanner.py path/to/email.eml")
        exit(1)

    scan_email(sys.argv[1])
