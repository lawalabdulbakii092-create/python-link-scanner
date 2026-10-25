
from urllib.parse import urlparse, unquote
import ipaddress

SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "is.gd",
    "cutt.ly", "rb.gy", "shorturl.at"
}

SUSPICIOUS_WORDS = {
    "login", "verify", "verification", "password",
    "account", "secure", "wallet", "claim",
    "gift", "free", "urgent", "update", "bank"
}

def scan_url(raw_url):
    warnings = []
    score = 0

    raw_url = raw_url.strip()

    if not raw_url:
        return 0, ["No URL was entered."]

    # Do not open or connect to the URL.
    if any(ord(c) < 32 for c in raw_url):
        return 100, ["URL contains unusual control characters."]

    candidate = raw_url
    if "://" not in candidate:
        candidate = "https://" + candidate

    try:
        parts = urlparse(candidate)
        host = parts.hostname
        port = parts.port
    except ValueError:
        return 100, ["URL format or port number is invalid."]

    if parts.scheme.lower() not in ("http", "https"):
        warnings.append("Unexpected URL protocol.")
        score += 30

    if not host:
        warnings.append("No valid hostname was found.")
        return 100, warnings

    host = host.lower().rstrip(".")

    # IP address instead of a familiar domain name
    try:
        ipaddress.ip_address(host)
        warnings.append(
            "The link uses an IP address rather than a domain name."
        )
        score += 25
    except ValueError:
        pass

    # Username/password embedded in the URL
    if parts.username is not None or parts.password is not None:
        warnings.append(
            "The URL contains text before @ that may disguise its destination."
        )
        score += 30

    # Encoded international domain name
    if "xn--" in host:
        warnings.append(
            "The domain uses punycode. Check carefully for look-alike characters."
        )
        score += 15

    if host in SHORTENERS:
        warnings.append(
            "This is a URL-shortening service, so the final destination is hidden."
        )
        score += 15

    labels = host.split(".")
    if len(labels) >= 5:
        warnings.append(
            "The hostname has many subdomain levels; verify the actual domain."
        )
        score += 10

    decoded = unquote(raw_url).lower()
    found_words = sorted(
        word for word in SUSPICIOUS_WORDS if word in decoded
    )
    if found_words:
        warnings.append(
            "Contains phishing-associated words: " + ", ".join(found_words)
        )
        score += min(20, 5 * len(found_words))

    if parts.scheme.lower() == "http":
        warnings.append(
            "Uses HTTP rather than HTTPS; the connection is not encrypted."
        )
        score += 10

    if port is not None and port not in (80, 443):
        warnings.append(
            "Uses an unusual web port. Confirm that this is expected."
        )
        score += 10

    if len(raw_url) > 200:
        warnings.append(
            "The URL is unusually long; inspect it carefully."
        )
        score += 10

    if not warnings:
        warnings.append(
            "No obvious warning signs were found by these basic checks."
        )

    return min(score, 100), warnings


def main():
    print("=" * 36)
    print("       PYTHON LINK SCANNER")
    print("=" * 36)
    print("Offline check: the link will NOT be opened.")
    print("Never enter passwords or private information.")
    print("Type exit to quit.")

    while True:
        url = input("\nPaste a URL to inspect: ").strip()

        if url.lower() == "exit":
            print("Scanner closed.")
            break

        score, warnings = scan_url(url)

        print("\n--- SCAN REPORT ---")
        print("Warning score:", score, "/ 100")

        if score >= 40:
            print("Assessment: HIGHER RISK")
        elif score >= 15:
            print("Assessment: CAUTION")
        else:
            print("Assessment: FEW BASIC WARNING SIGNS")

        for warning in warnings:
            print("-", warning)

        print("\nImportant: this is a heuristic, not a malware detector.")
        print("A low score does NOT prove a link is safe.")


if __name__ == "__main__":
    main()
