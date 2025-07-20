import email
from email import policy
from email.parser import BytesParser
import re
import requests

# === ISI API KEY KAMU DI SINI ===
ABUSEIPDB_API_KEY = "7e092339f2477cc269c5ca02e7473ead9ea7b0d1e0eaa588ead199ee8827f45fd638f95891a7f496"

# --- Parse Email Headers ---
def parse_email_headers(file_path):
    with open(file_path, 'rb') as f:
        msg = BytesParser(policy=policy.default).parse(f)

    headers = {
        "From": msg["From"],
        "To": msg["To"],
        "Subject": msg["Subject"],
        "Received": msg.get_all("Received"),
        "Return-Path": msg["Return-Path"],
        "Authentication-Results": msg["Authentication-Results"],
        "Received-SPF": msg["Received-SPF"],
        "DKIM-Signature": msg["DKIM-Signature"]
    }

    return headers

# --- Email Authentication Check ---
def analyze_auth_results(headers):
    results = {
        'SPF': 'fail',
        'DKIM': 'fail',
        'DMARC': 'fail'
    }

    auth_results = headers.get("Authentication-Results", "") or ""
    received_spf = headers.get("Received-SPF", "") or ""

    if 'spf=pass' in auth_results.lower() or 'pass' in received_spf.lower():
        results['SPF'] = 'pass'
    if 'dkim=pass' in auth_results.lower():
        results['DKIM'] = 'pass'
    if 'dmarc=pass' in auth_results.lower():
        results['DMARC'] = 'pass'

    return results

# --- Domain Mismatch Check ---
def extract_domain(email_address):
    match = re.search(r'@([\w\.-]+)', email_address or "")
    return match.group(1).lower() if match else None

def check_domain_mismatch(headers):
    from_address = headers.get("From", "")
    return_path = headers.get("Return-Path", "")
    auth_results = headers.get("Authentication-Results", "")

    from_domain = extract_domain(from_address)
    return_domain = extract_domain(return_path)

    auth_domain = None
    match = re.search(r'domain=([\w\.-]+)', auth_results or "")
    if match:
        auth_domain = match.group(1).lower()

    domains = set(filter(None, [from_domain, return_domain, auth_domain]))
    mismatch_detected = len(domains) > 1

    return {
        "from_domain": from_domain,
        "return_domain": return_domain,
        "auth_domain": auth_domain,
        "mismatch_detected": mismatch_detected
    }

# --- Extract Sender IP ---
def extract_sender_ip(headers):
    received_headers = headers.get("Received", [])
    if not received_headers:
        return None

    for line in received_headers[::-1]:  # earliest Received header first
        match = re.search(r'\[(\d+\.\d+\.\d+\.\d+)\]', line)
        if match:
            return match.group(1)
    return None

# --- AbuseIPDB Reputation Check ---
def check_ip_reputation(ip, api_key):
    url = "https://api.abuseipdb.com/api/v2/check"
    params = {'ipAddress': ip, 'maxAgeInDays': 90}
    headers = {'Accept': 'application/json', 'Key': api_key}

    try:
        response = requests.get(url, headers=headers, params=params)
        data = response.json().get('data', {})
        return {
            "ipAddress": ip,
            "abuseConfidenceScore": data.get("abuseConfidenceScore", 0),
            "countryCode": data.get("countryCode", "Unknown"),
            "domain": data.get("domain", "Unknown"),
            "isWhitelisted": data.get("isWhitelisted", False),
        }
    except Exception as e:
        return {"error": str(e)}

# --- ANALISA UTAMA ---
def analyze_email_headers(file_path):
    headers = parse_email_headers(file_path)
    auth_check = analyze_auth_results(headers)
    domain_check = check_domain_mismatch(headers)
    sender_ip = extract_sender_ip(headers)
    ip_report = check_ip_reputation(sender_ip, ABUSEIPDB_API_KEY) if sender_ip else {"message": "No valid IP found"}

    return {
        "authentication": auth_check,
        "domain_check": domain_check,
        "sender_ip": sender_ip,
        "ip_reputation": ip_report
    }

    # Print output rapi seperti sebelumnya
    print("\n=== Email Authentication ===")
    for k, v in auth_check.items():
        print(f"{k}: {v}")

    print("\n=== Sender Domain Analysis ===")
    print(f"From domain     : {domain_check['from_domain']}")
    print(f"Return-Path     : {domain_check['return_domain']}")
    print(f"Auth Result dom.: {domain_check['auth_domain']}")
    print("⚠️ Mismatch Detected!" if domain_check['mismatch_detected'] else "✅ Domains Match")

    if sender_ip:
        print("\n=== Sender IP Reputation ===")
        for k, v in ip_report.items():
            print(f"{k}: {v}")
    else:
        print("\nNo valid sender IP found.")

# --- CLI ENTRY POINT ---
if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2:
        print("Usage: python email_analysis.py path/to/email.eml")
        sys.exit(1)

    email_path = sys.argv[1]
    analyze_email_headers(email_path)
