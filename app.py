from fastapi import FastAPI, HTTPException, UploadFile, File
from pydantic import BaseModel
from fastapi.responses import JSONResponse

# URL + File model
import joblib
from url_scanner import extract_features, check_whois_safety, is_definitely_malicious_url
from urllib.parse import urlparse
import numpy as np
from file import scan_file 
import os

# Email scanning modules
from classify_eml import classify_eml
from attachment_analysis import (
    extract_attachments_and_urls,
    scan_file_virustotal,
    scan_url_virustotal,
    is_obfuscated_url
)
from email_analysis import analyze_email_headers

import shutil
import uuid
import re

app = FastAPI()

# Load ML model
model = joblib.load("phishing_xgboost_model.pkl")

# === URL Prediction Model ===
class URLRequest(BaseModel):
    url: str

feature_names = [
    "URL Length", "Dots in URL", "Repeated Digits in URL", "Digits in URL",
    "Special Chars in URL", "Hyphens in URL", "Underscores in URL", "Slashes in URL",
    "Question Marks in URL", "Equals in URL", "At Signs in URL", "Dollar Signs in URL",
    "Exclamations in URL", "Hashtags in URL", "Percent Signs in URL",
    "Domain Length", "Dots in Domain", "Hyphens in Domain", "Special Chars in Domain (bool)",
    "Special Chars in Domain (count)", "Digits in Domain (bool)", "Digits in Domain (count)",
    "Repeated Digits in Domain", "Subdomains", "Dot in Subdomain", "Hyphen in Subdomain",
    "Avg Subdomain Length", "Avg Dots in Subdomain", "Avg Hyphens in Subdomain",
    "Special Chars in Subdomain (bool)", "Special Chars in Subdomain (count)",
    "Digits in Subdomain (bool)", "Digits in Subdomain (count)",
    "Repeated Digits in Subdomain", "Has Path", "Path Length", "Has Query",
    "Has Fragment", "Has Anchor", "Entropy of URL", "Entropy of Domain"
]

@app.post("/predict/url")
async def predict_url(request: URLRequest):
    url = request.url
    if not url:
        raise HTTPException(status_code=400, detail="No URL provided")
    
    if is_definitely_malicious_url(url):
        return JSONResponse(content={
            "result": "Malicious",
            "reason": "Detected by rule-based system",
            "features": None
        })

    try:
        features = extract_features(url)[0]
        prediction = model.predict([features])[0]
        confidence = float(np.max(model.predict_proba([features])[0])) if hasattr(model, "predict_proba") else None
        parsed_domain = urlparse(url).netloc
        whois_safe = check_whois_safety(parsed_domain)

        if prediction == 1:
            if confidence is not None and 0.61 <= confidence <= 0.79:
                result = "Suspicious"
            elif not whois_safe:
                result = "Not Safe"
            else:
                result = "Safe"
        else:
            result = "Safe" if whois_safe else "Suspicious"

        def get_reason(result, confidence, whois_safe):
            if result == "Suspicious":
                if confidence and 0.61 <= confidence <= 0.79:
                    return "Confidence score is moderate."
                elif not whois_safe:
                    return "WHOIS data shows domain is likely unsafe."
                return "Detected as borderline suspicious."
            elif result == "Not Safe":
                return "Domain flagged by WHOIS or risky structure."
            elif result == "Safe":
                return "Model and WHOIS check both passed."
            return "Detected by rule-based system."

        return JSONResponse(content={
            "result": result,
            "model_prediction": "Malicious" if prediction == 1 else "Legitimate",
            "confidence": f"{round(confidence * 100, 2)}%" if confidence is not None else None,
            "whois_safe": whois_safe,
            "features": dict(zip(feature_names, features.tolist())),
            "reason": get_reason(result, confidence, whois_safe)
        })

    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))


@app.post("/predict/file")
async def predict_file(file: UploadFile = File(...)):
    file_path = f"/tmp/{file.filename}"
    try:
        contents = await file.read()
        with open(file_path, "wb") as f:
            f.write(contents)

        scan_result = scan_file(file_path)
        if "error" in scan_result:
            raise HTTPException(status_code=400, detail=scan_result["error"])

        file_info = scan_result["file_info"]
        indicators = scan_result["indicators"]

        def get_indicator(indicators, key):
            return next((i["value"] for i in indicators if i["type"] == key), None)

        return JSONResponse(content={
            "result": scan_result["classification"],
            "threat_score": scan_result["threat_score"],
            "features": {
                "filename": file_info.get("path", file.filename),
                "file_size": file_info.get("size"),
                "file_type": file_info.get("file_type"),
                "md5": file_info.get("md5"),
                "sha1": file_info.get("sha1"),
                "sha256": file_info.get("sha256"),
                "entropy": get_indicator(indicators, "entropy"),
                "non_ascii_ratio": get_indicator(indicators, "non_ascii_ratio"),
                "sandbox_detected": get_indicator(indicators, "sandbox"),
                "embedded_urls_ips": get_indicator(indicators, "url/ip"),
                "suspicious_api_calls": [i["value"] for i in indicators if i["type"] == "api"],
                "strings_sample": file_info.get("strings_found", [])
            },
            "indicators": indicators,
            "verdicts": scan_result["verdicts"]
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    finally:
        if os.path.exists(file_path):
            os.remove(file_path)


@app.post("/scan-email/")
async def scan_email(file: UploadFile = File(...)):
    temp_filename = f"temp_{uuid.uuid4()}.eml"
    with open(temp_filename, "wb") as f:
        shutil.copyfileobj(file.file, f)

    try:
        label, confidence = classify_eml(temp_filename)
        attachments, urls = extract_attachments_and_urls(temp_filename)

        attachment_results = []
        for att in attachments:
            scan_result = scan_file_virustotal(att)
            parts = dict(re.findall(r'(\w+):\s*(\d+)', scan_result))
            attachment_results.append({
                "file": os.path.basename(att),
                "malicious": int(parts.get("Malicious", 0)),
                "suspicious": int(parts.get("Suspicious", 0)),
                "harmless": int(parts.get("Harmless", 0))
            })

        url_results = []
        for url in urls:
            vt_result = scan_url_virustotal(url)
            stats = dict(re.findall(r'(\w+):\s*(\d+)', vt_result))
            url_results.append({
                "url": url,
                "obfuscated": is_obfuscated_url(url),
                "malicious": int(stats.get("Malicious", 0)),
                "suspicious": int(stats.get("Suspicious", 0)),
                "harmless": int(stats.get("Harmless", 0))
            })

        header_analysis = analyze_email_headers(temp_filename)

        header_score_raw = 0
        auth = header_analysis["authentication"]
        if auth["SPF"] == "pass": header_score_raw += 0.15
        if auth["DKIM"] == "pass": header_score_raw += 0.15
        if auth["DMARC"] == "pass": header_score_raw += 0.10
        if not header_analysis["domain_check"]["mismatch_detected"]: header_score_raw += 0.05
        if header_analysis["ip_reputation"]["abuseConfidenceScore"] <= 10: header_score_raw += 0.05
        if header_analysis["ip_reputation"]["isWhitelisted"]: header_score_raw += 0.05

        url_or_attachment_found = len(attachment_results) > 0 or len(url_results) > 0
        threat_found = any(att["malicious"] > 0 for att in attachment_results) or any(url["malicious"] > 0 for url in url_results)
        suspicious_found = any(att["suspicious"] > 0 for att in attachment_results) or any(url["suspicious"] > 0 for url in url_results)

        attachment_score_raw = 0.3
        if threat_found: attachment_score_raw = 0.0
        elif suspicious_found: attachment_score_raw = 0.15
        elif not url_or_attachment_found: attachment_score_raw = 0.0

        content_score_raw = 0.2 if label == 0 else 0.0

        total_score = round(
            (header_score_raw / 0.6) * (0.7 if not url_or_attachment_found else 0.5) +
            (content_score_raw / 0.2) * (0.3 if not url_or_attachment_found else 0.2) +
            (attachment_score_raw / 0.3) * (0.0 if not url_or_attachment_found else 0.3),
            2
        )

        status = "Safe" if total_score >= 0.7 else "Suspicious (Review Needed)" if total_score >= 0.4 else "Not Safe"

        return {
            "classification": {
                "label": "Phishing/Spam" if label == 1 else "Legitimate",
                "confidence": round(confidence, 2)
            },
            "attachments": attachment_results,
            "urls": url_results,
            "header_analysis": header_analysis,
            "final_assessment": {
                "status": status,
                "score": total_score
            }
        }

    finally:
        if os.path.exists(temp_filename):
            os.remove(temp_filename)
