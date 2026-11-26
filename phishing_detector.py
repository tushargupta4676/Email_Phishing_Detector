
import re
import json
import argparse

from email import policy
from email.parser import BytesParser
from urllib.parse import urlparse


# Suspicious words frequently found in phishing emails
PHISHING_KEYWORDS = [
    "urgent",
    "verify your account",
    "password expired",
    "account suspended",
    "click here",
    "confirm your identity",
    "unusual activity",
    "immediate action required",
    "payment failed",
    "login immediately"
]

# Common URL shorteners
URL_SHORTENERS = [
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly"
]

# File extensions that deserve additional scrutiny
RISKY_EXTENSIONS = [
    ".exe",
    ".scr",
    ".bat",
    ".cmd",
    ".js",
    ".vbs",
    ".ps1",
    ".hta"
]


def extract_urls(text):
    """Extract URLs from email text."""

    pattern = r'https?://[^\s<>"\']+'
    return re.findall(pattern, text, re.IGNORECASE)


def analyse_url(url):
    """Check a URL for suspicious characteristics."""

    findings = []

    parsed = urlparse(url)
    hostname = (parsed.hostname or "").lower()

    if not hostname:
        return findings

    if parsed.scheme != "https":
        findings.append("URL does not use HTTPS")

    if hostname in URL_SHORTENERS:
        findings.append("URL uses a known shortening service")

    if re.fullmatch(r"\d{1,3}(?:\.\d{1,3}){3}", hostname):
        findings.append("URL uses an IP address instead of a domain")

    if "xn--" in hostname:
        findings.append("URL contains an internationalized domain name")

    if hostname.count(".") >= 4:
        findings.append("URL contains an unusually deep subdomain structure")

    return findings


def analyse_email(file_path):
    """Parse and analyse an .eml email."""

    with open(file_path, "rb") as email_file:
        message = BytesParser(policy=policy.default).parse(email_file)

    findings = []
    score = 0

    sender = str(message.get("From", ""))
    reply_to = str(message.get("Reply-To", ""))

    subject = str(message.get("Subject", ""))

    body_parts = []
    attachment_names = []

    # Extract email body and attachment filenames
    for part in message.walk():

        if part.get_content_disposition() == "attachment":
            filename = part.get_filename()

            if filename:
                attachment_names.append(filename)

        elif part.get_content_type() == "text/plain":
            try:
                body_parts.append(part.get_content())
            except Exception:
                pass

    body = "\n".join(body_parts)
    email_text = subject + " " + body

    # 1. Check suspicious keywords
    for keyword in PHISHING_KEYWORDS:

        if keyword in email_text.lower():
            findings.append(
                f"Suspicious keyword detected: {keyword}"
            )
            score += 10

    # 2. Check Reply-To mismatch
    if reply_to:

        sender_match = re.search(
            r'@([A-Za-z0-9.-]+)',
            sender
        )

        reply_match = re.search(
            r'@([A-Za-z0-9.-]+)',
            reply_to
        )

        if sender_match and reply_match:

            sender_domain = sender_match.group(1).lower()
            reply_domain = reply_match.group(1).lower()

            if sender_domain != reply_domain:
                findings.append(
                    "Sender domain and Reply-To domain differ"
                )
                score += 25

    # 3. Extract and inspect URLs
    urls = extract_urls(email_text)

    for url in urls:

        url_findings = analyse_url(url)

        for finding in url_findings:
            findings.append(f"{finding}: {url}")
            score += 15

    # 4. Inspect attachments
    for filename in attachment_names:

        if filename.lower().endswith(tuple(RISKY_EXTENSIONS)):

            findings.append(
                f"Potentially dangerous attachment: {filename}"
            )

            score += 25

    # 5. Calculate final risk level
    score = min(score, 100)

    if score >= 60:
        risk = "HIGH"
    elif score >= 30:
        risk = "MEDIUM"
    else:
        risk = "LOW"

    return {
        "sender": sender,
        "subject": subject,
        "risk_score": score,
        "risk_level": risk,
        "findings": findings,
        "urls_found": urls,
        "attachments": attachment_names
    }


def main():

    parser = argparse.ArgumentParser(
        description="Email Phishing Detection Tool"
    )

    parser.add_argument(
        "email_file",
        help="Path to an .eml email file"
    )

    args = parser.parse_args()

    try:
        report = analyse_email(args.email_file)

        print("\n===== EMAIL SECURITY REPORT =====")

        print("Sender:", report["sender"])
        print("Subject:", report["subject"])
        print("Risk Score:", report["risk_score"], "/ 100")
        print("Risk Level:", report["risk_level"])

        print("\nFindings:")

        if report["findings"]:
            for finding in report["findings"]:
                print("[-]", finding)
        else:
            print("[+] No suspicious indicators detected.")

        print("\nURLs:", report["urls_found"])
        print("Attachments:", report["attachments"])

        # Export report to JSON
        with open("report.json", "w", encoding="utf-8") as file:
            json.dump(report, file, indent=4)

        print("\nReport saved as report.json")

    except (OSError, ValueError) as error:
        print("Error:", error)


if __name__ == "__main__":
    main()
