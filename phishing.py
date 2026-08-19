#!/usr/bin/env python3

"""
PHISHING AWARENESS ANALYZER
Cyber Security Project 3

Purpose:
Analyze an email or message and identify common
phishing indicators.
"""

import re
from urllib.parse import urlparse


# -----------------------------------------
# SUSPICIOUS KEYWORDS
# -----------------------------------------

SUSPICIOUS_KEYWORDS = {
    "Urgency": [
        "urgent",
        "immediately",
        "act now",
        "action required",
        "final warning",
        "account will be closed",
        "expires today"
    ],

    "Credentials": [
        "password",
        "login",
        "sign in",
        "verify your account",
        "confirm your identity",
        "username",
        "otp",
        "verification code"
    ],

    "Financial": [
        "payment",
        "bank account",
        "credit card",
        "debit card",
        "refund",
        "invoice",
        "gift card",
        "wire transfer"
    ],

    "Rewards": [
        "winner",
        "won",
        "prize",
        "reward",
        "lottery",
        "free gift",
        "claim now"
    ]
}


# -----------------------------------------
# URL PATTERN
# -----------------------------------------

URL_PATTERN = re.compile(
    r"(https?://[^\s<>\"']+|www\.[^\s<>\"']+)",
    re.IGNORECASE
)


# -----------------------------------------
# EXTRACT URLs
# -----------------------------------------

def extract_urls(message):
    """
    Find all URLs present in the message.
    """
    return URL_PATTERN.findall(message)


# -----------------------------------------
# NORMALIZE URL
# -----------------------------------------

def normalize_url(url):
    """
    Add HTTP scheme if URL starts with www.
    """
    if url.lower().startswith("www."):
        return "http://" + url

    return url


# -----------------------------------------
# ANALYZE URL
# -----------------------------------------

def analyze_url(url):

    flags = []

    parsed_url = urlparse(normalize_url(url))

    domain = parsed_url.hostname or ""

    # Check HTTP
    if parsed_url.scheme.lower() == "http":
        flags.append(
            "Uses HTTP instead of HTTPS"
        )

    # Check IP address
    ip_pattern = r"^\d{1,3}(?:\.\d{1,3}){3}$"

    if re.match(ip_pattern, domain):
        flags.append(
            "Uses an IP address instead of a domain name"
        )

    # Check @ symbol
    if "@" in url:
        flags.append(
            "Contains @ symbol which may disguise destination"
        )

    # Check very long URL
    if len(url) > 100:
        flags.append(
            "URL is unusually long"
        )

    # Check multiple subdomains
    if domain.count(".") >= 3:
        flags.append(
            "Contains many subdomains"
        )

    # Check hyphen
    if "-" in domain:
        flags.append(
            "Domain contains hyphens"
        )

    # Suspicious TLDs
    suspicious_tlds = (
        ".xyz",
        ".top",
        ".click",
        ".tk",
        ".zip",
        ".mov"
    )

    if domain.lower().endswith(suspicious_tlds):
        flags.append(
            "Uses a potentially suspicious domain extension"
        )

    return flags


# -----------------------------------------
# ANALYZE MESSAGE
# -----------------------------------------

def analyze_message(message):

    message_lower = message.lower()

    red_flags = []

    score = 0

    # -------------------------------------
    # KEYWORD ANALYSIS
    # -------------------------------------

    for category, keywords in SUSPICIOUS_KEYWORDS.items():

        found_keywords = []

        for keyword in keywords:

            if keyword in message_lower:
                found_keywords.append(keyword)

        if found_keywords:

            red_flags.append(
                f"{category} indicators: "
                + ", ".join(found_keywords)
            )

            score += min(
                20,
                len(found_keywords) * 5
            )

    # -------------------------------------
    # URL ANALYSIS
    # -------------------------------------

    urls = extract_urls(message)

    if urls:

        red_flags.append(
            f"Message contains {len(urls)} link(s)"
        )

        score += 5

    for url in urls:

        url_flags = analyze_url(url)

        for flag in url_flags:

            red_flags.append(
                f"URL red flag: {flag}"
            )

            score += 8

    # -------------------------------------
    # GENERIC GREETING
    # -------------------------------------

    generic_greeting = re.search(
        r"\bdear (customer|user|member|sir|madam)\b",
        message_lower
    )

    if generic_greeting:

        red_flags.append(
            "Uses a generic greeting"
        )

        score += 5

    # -------------------------------------
    # CLICK INSTRUCTION
    # -------------------------------------

    click_pattern = re.search(
        r"\b(click|tap)\s+(here|this link)\b",
        message_lower
    )

    if click_pattern:

        red_flags.append(
            "Directly instructs the user to click a link"
        )

        score += 7

    # -------------------------------------
    # SENSITIVE INFORMATION REQUEST
    # -------------------------------------

    sensitive_pattern = re.search(
        r"\b(send|share|provide|enter)\b.{0,50}"
        r"\b(password|otp|pin|cvv|card)\b",
        message_lower
    )

    if sensitive_pattern:

        red_flags.append(
            "Requests sensitive credentials or financial information"
        )

        score += 15

    # -------------------------------------
    # LIMIT SCORE
    # -------------------------------------

    score = min(score, 100)

    # -------------------------------------
    # DETERMINE RISK LEVEL
    # -------------------------------------

    if score >= 70:

        risk_level = "HIGH"

    elif score >= 40:

        risk_level = "MEDIUM"

    else:

        risk_level = "LOW"

    return {
        "score": score,
        "risk": risk_level,
        "urls": urls,
        "red_flags": red_flags
    }


# -----------------------------------------
# DISPLAY REPORT
# -----------------------------------------

def display_report(result):

    print("\n")
    print("=" * 60)

    print(
        "          PHISHING AWARENESS ANALYSIS"
    )

    print("=" * 60)

    print(
        f"\nRisk Score : {result['score']}/100"
    )

    print(
        f"Risk Level : {result['risk']}"
    )

    # -------------------------------------
    # LINKS
    # -------------------------------------

    print("\nSuspicious Links:")

    if result["urls"]:

        for url in result["urls"]:

            print(
                f"  - {url}"
            )

    else:

        print(
            "  - No URLs found"
        )

    # -------------------------------------
    # RED FLAGS
    # -------------------------------------

    print("\nRed Flags:")

    if result["red_flags"]:

        for number, flag in enumerate(
            result["red_flags"],
            start=1
        ):

            print(
                f"  {number}. {flag}"
            )

    else:

        print(
            "  - No obvious red flags detected"
        )

    # -------------------------------------
    # SAFETY EXPLANATION
    # -------------------------------------

    print("\nSafety Assessment:")

    if result["risk"] == "HIGH":

        print(
            "  This message contains multiple "
            "phishing indicators."
        )

        print(
            "  Do not click links or provide "
            "sensitive information."
        )

    elif result["risk"] == "MEDIUM":

        print(
            "  This message contains some "
            "suspicious indicators."
        )

        print(
            "  Verify the sender and destination "
            "independently."
        )

    else:

        print(
            "  Few phishing indicators were detected."
        )

        print(
            "  Still verify unexpected messages "
            "before taking action."
        )

    print("=" * 60)


# -----------------------------------------
# MAIN PROGRAM
# -----------------------------------------

def main():

    print(
        "PHISHING AWARENESS ANALYZER"
    )

    print(
        "Cyber Security Project 3"
    )

    print(
        "\nPaste an email or message below."
    )

    print(
        "Type END on a new line when finished.\n"
    )

    lines = []

    while True:

        try:

            line = input()

        except EOFError:

            break

        if line.strip().upper() == "END":

            break

        lines.append(line)

    message = "\n".join(lines).strip()

    if not message:

        print(
            "No message entered."
        )

        return

    # Analyze message
    result = analyze_message(message)

    # Display result
    display_report(result)


# -----------------------------------------
# PROGRAM START
# -----------------------------------------

if __name__ == "__main__":

    main()