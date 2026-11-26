
# Email Phishing Detection Tool

## Overview
A Python-based defensive cybersecurity tool
that analyses email files (.eml) to identify
potential phishing indicators.

## Features
- Suspicious keyword detection
- URL extraction and inspection
- Sender and Reply-To mismatch detection
- Suspicious attachment extension detection
- Rule-based risk scoring
- JSON security report generation

## Technologies
- Python 3
- Regular Expressions
- Email Parsing
- URL Parsing
- JSON

## Execution

python phishing_detector.py sample_email.eml

## Output
The application generates a JSON report
containing the sender, subject, risk score,
risk classification and detected indicators.

## Limitations
This is a rule-based prototype. It does not
guarantee detection of all phishing emails.
