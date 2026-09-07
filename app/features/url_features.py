from urllib.parse import urlparse, urlunparse
import math
import re
import ipaddress


# ============================================================
# FEATURE NAMES
# IMPORTANT:
# KEEP THIS EXACT ORDER BECAUSE THE ML MODEL EXPECTS 41 FEATURES
# ============================================================

FEATURE_NAMES = [
    "url_length",
    "domain_length",
    "path_length",
    "query_length",
    "num_dots",
    "num_hyphens",
    "num_digits",
    "num_slashes",
    "num_parameters",
    "num_subdomains",
    "num_special_chars",
    "is_https",
    "is_http",
    "has_ip",
    "unusual_port",
    "has_at_symbol",
    "suspicious_tld",
    "url_shortener",
    "domain_entropy",
    "domain_age_days",
    "registration_info",
    "suspicious_keywords",
    "brand_impersonation",
    "typosquatting",
    "punycode",
    "homograph",
    "dns_exists",
    "dns_ip_count",
    "dns_private_ip",
    "dns_suspicious",
    "threat_intelligence",
    "historical_reputation",
    "redirect_count",
    "redirect_domain_change",
    "redirect_https_downgrade",
    "form_count",
    "password_form",
    "external_resource_ratio",
    "javascript_count",
    "iframe_count",
    "suspicious_script",
]


# ============================================================
# CONSTANTS
# ============================================================

SUSPICIOUS_TLDS = {
    "tk", "ml", "ga", "cf", "gq",
    "top", "xyz", "click", "download",
    "zip", "review", "country", "work",
    "party", "stream", "racing", "win",
    "bid", "loan", "date", "faith",
    "science", "men", "live",
}


URL_SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "cutt.ly",
    "shorturl.at",
    "rebrand.ly",
    "tiny.cc",
    "lnkd.in",
}


SUSPICIOUS_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "account",
    "update",
    "secure",
    "security",
    "password",
    "passwd",
    "credential",
    "wallet",
    "bank",
    "payment",
    "invoice",
    "confirm",
    "authentication",
    "authorize",
    "authorization",
    "recover",
    "reset",
    "unlock",
    "suspended",
    "urgent",
    "alert",
    "bonus",
    "free",
    "claim",
}


KNOWN_BRANDS = {
    "google",
    "facebook",
    "instagram",
    "microsoft",
    "apple",
    "amazon",
    "paypal",
    "netflix",
    "linkedin",
    "github",
    "dropbox",
    "whatsapp",
    "telegram",
    "twitter",
    "x",
}


# ============================================================
# LEGITIMATE COMMON DOMAINS
#
# This is NOT used to blindly mark a site safe.
# It is only used to identify the legitimate brand/domain
# structure correctly.
# ============================================================

KNOWN_LEGITIMATE_DOMAINS = {
    "google.com",
    "google.co.in",
    "youtube.com",
    "facebook.com",
    "instagram.com",
    "microsoft.com",
    "apple.com",
    "amazon.com",
    "amazon.in",
    "paypal.com",
    "netflix.com",
    "linkedin.com",
    "github.com",
    "dropbox.com",
    "whatsapp.com",
    "telegram.org",
    "x.com",
    "twitter.com",
}


# ============================================================
# BASIC HELPERS
# ============================================================

def safe_int(value):
    try:
        return int(value)
    except Exception:
        return 0


def safe_float(value):
    try:
        return float(value)
    except Exception:
        return 0.0


# ============================================================
# URL NORMALIZATION
# ============================================================

def normalize_url(url):
    """
    Normalize user input into a URL that urlparse() can understand.

    Examples:

        google.com
        www.google.com
        https://google.com
        HTTPS://WWW.GOOGLE.COM/
        google.com/search?q=test

    are all accepted.

    We do NOT remove the path/query because those can contain
    important security information.
    """

    if url is None:
        return ""

    url = str(url).strip()

    if not url:
        return ""

    # Remove surrounding angle brackets sometimes copied from text.
    url = url.strip("<>")

    # Remove spaces accidentally inserted at the beginning/end.
    url = url.strip()

    # If the user enters:
    #     localhost:8501
    #     192.168.1.1:8080
    # urlparse can interpret "localhost" as a scheme.
    #
    # Only accept http/https as an actual scheme.
    parsed = urlparse(url)

    if parsed.scheme.lower() not in {"http", "https"}:
        url = "https://" + url

    # Remove accidental duplicate leading schemes.
    url = re.sub(
        r"^(https?://)+",
        lambda m: "https://" if m.group(0).lower().count("https://") else "http://",
        url,
        flags=re.IGNORECASE,
    )

    return url


def parse_url(url):
    """
    Safely parse a URL.

    Returns:
        normalized_url, parsed_url
    """

    normalized = normalize_url(url)

    if not normalized:
        return "", urlparse("")

    try:
        parsed = urlparse(normalized)
        return normalized, parsed
    except Exception:
        return normalized, urlparse("")


def get_domain(url):
    """
    Extract hostname without the port.

    Examples:
        google.com -> google.com
        www.google.com -> www.google.com
        192.168.1.1:8080 -> 192.168.1.1
    """

    _, parsed = parse_url(url)

    try:
        return (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        return ""


def get_registered_domain(domain):
    """
    Approximate registered/root domain without requiring
    an external package.

    Examples:
        www.google.com -> google.com
        login.accounts.google.com -> google.com

    For country-code domains this is intentionally conservative.
    """

    if not domain:
        return ""

    if is_ip_address(domain):
        return domain

    parts = domain.lower().rstrip(".").split(".")

    if len(parts) <= 2:
        return domain.lower().rstrip(".")

    # Common second-level country-code suffixes.
    common_second_level = {
        "co.uk",
        "org.uk",
        "ac.uk",
        "gov.uk",
        "com.au",
        "net.au",
        "org.au",
        "co.in",
        "firm.in",
        "net.in",
        "org.in",
        "gen.in",
        "ind.in",
    }

    suffix2 = ".".join(parts[-2:])

    if suffix2 in common_second_level and len(parts) >= 3:
        return ".".join(parts[-3:])

    return ".".join(parts[-2:])


def is_known_legitimate_domain(domain):
    """
    Check exact registered/root domain against the known
    legitimate-domain set.

    This does NOT automatically classify the URL as safe.
    """

    registered = get_registered_domain(domain)

    return registered in KNOWN_LEGITIMATE_DOMAINS


# ============================================================
# ENTROPY
# ============================================================

def calculate_entropy(text):
    if not text:
        return 0.0

    counts = {}

    for char in text:
        counts[char] = counts.get(char, 0) + 1

    length = len(text)

    entropy = 0.0

    for count in counts.values():
        probability = count / length

        if probability > 0:
            entropy -= probability * math.log2(probability)

    return entropy


# ============================================================
# IP HELPERS
# ============================================================

def is_ip_address(domain):
    if not domain:
        return False

    try:
        ipaddress.ip_address(domain)
        return True
    except Exception:
        return False


def is_private_ip(domain):
    if not domain:
        return False

    try:
        return ipaddress.ip_address(domain).is_private
    except Exception:
        return False


# ============================================================
# DOMAIN FEATURES
# ============================================================

def count_subdomains(domain):

    if not domain:
        return 0

    if is_ip_address(domain):
        return 0

    parts = domain.split(".")

    if len(parts) <= 2:
        return 0

    registered = get_registered_domain(domain)

    registered_parts = registered.split(".")

    return max(
        0,
        len(parts) - len(registered_parts)
    )


def detect_punycode(domain):

    if not domain:
        return 0

    return int(
        any(
            part.lower().startswith("xn--")
            for part in domain.split(".")
        )
    )


def detect_homograph(domain):

    if not domain:
        return 0

    # Unicode characters.
    if any(ord(c) > 127 for c in domain):
        return 1

    # Punycode is also an internationalized domain representation.
    if detect_punycode(domain):
        return 1

    return 0


def detect_typosquatting(domain):

    if not domain:
        return 0

    registered = get_registered_domain(domain)

    if is_ip_address(registered):
        return 0

    labels = registered.split(".")

    if not labels:
        return 0

    domain_name = labels[0].lower()

    suspicious_patterns = {
        "g00gle",
        "go0gle",
        "goog1e",
        "googIe",
        "faceb00k",
        "facebok",
        "faceboook",
        "micros0ft",
        "microsofft",
        "paypa1",
        "paypall",
        "amaz0n",
        "amazoon",
        "app1e",
        "appple",
        "netfl1x",
        "netfliix",
        "linkedln",
        "github1",
        "whatsap",
        "whatsapp-login",
    }

    if domain_name in suspicious_patterns:
        return 1

    # Do NOT mark every brand-containing hostname as typosquatting.
    #
    # For example:
    #   google.com
    #   google.co.in
    #
    # must not be considered typosquatting.

    for brand in KNOWN_BRANDS:

        if brand == "x":
            continue

        if domain_name == brand:
            continue

        # Obvious brand impersonation inside the domain.
        if brand in domain_name:

            # Require some additional evidence of manipulation.
            altered = (
                domain_name.replace("0", "o")
                .replace("1", "l")
            )

            if altered != brand:
                return 1

    return 0


def detect_brand_impersonation(domain, path):

    if not domain:
        return 0

    registered = get_registered_domain(domain)

    combined = f"{domain} {path}".lower()

    domain_name = registered.split(".")[0].lower()

    # Legitimate root domain should not be marked as impersonation.
    if registered in KNOWN_LEGITIMATE_DOMAINS:
        return 0

    for brand in KNOWN_BRANDS:

        if brand == "x":
            continue

        # Brand appears in a domain that isn't the legitimate domain.
        if brand in domain_name:

            suspicious_context = any(
                word in combined
                for word in {
                    "login",
                    "verify",
                    "secure",
                    "account",
                    "update",
                    "signin",
                    "authentication",
                    "password",
                }
            )

            if suspicious_context:
                return 1

            # Obvious substitutions.
            normalized_name = (
                domain_name
                .replace("0", "o")
                .replace("1", "l")
            )

            if normalized_name != brand:
                return 1

    return 0


# ============================================================
# URL VALIDATION
# ============================================================

def is_valid_url(url):

    normalized, parsed = parse_url(url)

    if not normalized:
        return False

    try:
        hostname = parsed.hostname
    except Exception:
        return False

    if not hostname:
        return False

    hostname = hostname.rstrip(".")

    # IP address is valid.
    if is_ip_address(hostname):
        return True

    # Hostname must contain valid characters.
    if len(hostname) > 253:
        return False

    if any(
        len(label) > 63
        for label in hostname.split(".")
    ):
        return False

    # Basic hostname validation.
    if not re.match(
        r"^[A-Za-z0-9\u0080-\uffff.-]+$",
        hostname,
    ):
        return False

    return True


# ============================================================
# MAIN FEATURE EXTRACTION
# ============================================================

def get_features(url):
    """
    Extract exactly 41 features.

    IMPORTANT:
    No network request is made here.

    Dynamic features remain zero until populated by the
    dynamic analyzer.
    """

    normalized_url, parsed = parse_url(url)

    if not normalized_url:
        normalized_url = "https://"

    try:
        domain = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        domain = ""

    path = parsed.path or ""
    query = parsed.query or ""

    # ========================================================
    # BASIC URL FEATURES
    # ========================================================

    url_length = len(normalized_url)

    domain_length = len(domain)

    path_length = len(path)

    query_length = len(query)

    num_dots = normalized_url.count(".")

    num_hyphens = normalized_url.count("-")

    num_digits = sum(
        c.isdigit()
        for c in normalized_url
    )

    num_slashes = normalized_url.count("/")

    num_parameters = (
        len(
            [
                item
                for item in query.split("&")
                if item
            ]
        )
        if query
        else 0
    )

    num_subdomains = count_subdomains(domain)

    num_special_chars = len(
        re.findall(
            r"[^a-zA-Z0-9]",
            normalized_url,
        )
    )

    # ========================================================
    # PROTOCOL
    # ========================================================

    is_https = int(
        parsed.scheme.lower() == "https"
    )

    is_http = int(
        parsed.scheme.lower() == "http"
    )

    # ========================================================
    # IP
    # ========================================================

    has_ip = int(
        is_ip_address(domain)
    )

    # ========================================================
    # PORT
    # ========================================================

    unusual_port = 0

    try:

        port = parsed.port

        if port is not None:

            if port not in {80, 443}:
                unusual_port = 1

    except Exception:
        unusual_port = 0

    # ========================================================
    # @ SYMBOL
    # ========================================================

    has_at_symbol = int(
        "@" in normalized_url
    )

    # ========================================================
    # TLD
    # ========================================================

    tld = ""

    if "." in domain and not is_ip_address(domain):

        tld = domain.rsplit(
            ".",
            1
        )[-1].lower()

    suspicious_tld = int(
        tld in SUSPICIOUS_TLDS
    )

    # ========================================================
    # URL SHORTENER
    # ========================================================

    registered_domain = get_registered_domain(domain)

    url_shortener = int(
        domain in URL_SHORTENERS
        or registered_domain in URL_SHORTENERS
    )

    # ========================================================
    # ENTROPY
    # ========================================================

    domain_entropy = calculate_entropy(
        domain
    )

    # ========================================================
    # REGISTRATION
    #
    # These are intentionally zero because static extraction
    # does not perform WHOIS/network requests.
    # ========================================================

    domain_age_days = 0

    registration_info = 0

    # ========================================================
    # SUSPICIOUS KEYWORDS
    #
    # Check hostname + path + query.
    # ========================================================

    lower_url = normalized_url.lower()

    suspicious_keywords = int(
        any(
            keyword in lower_url
            for keyword in SUSPICIOUS_KEYWORDS
        )
    )

    # ========================================================
    # BRAND IMPERSONATION
    # ========================================================

    brand_impersonation = (
        detect_brand_impersonation(
            domain,
            path,
        )
    )

    # ========================================================
    # TYPOSQUATTING
    # ========================================================

    typosquatting = (
        detect_typosquatting(
            domain
        )
    )

    # ========================================================
    # PUNYCODE
    # ========================================================

    punycode = detect_punycode(
        domain
    )

    # ========================================================
    # HOMOGRAPH
    # ========================================================

    homograph = detect_homograph(
        domain
    )

    # ========================================================
    # DNS
    #
    # Static extractor intentionally does not perform DNS.
    # ========================================================

    dns_exists = 0

    dns_ip_count = 0

    dns_private_ip = int(
        is_private_ip(domain)
    )

    dns_suspicious = 0

    # ========================================================
    # THREAT INTELLIGENCE
    # ========================================================

    threat_intelligence = 0

    historical_reputation = 0

    # ========================================================
    # DYNAMIC BROWSER FEATURES
    # ========================================================

    redirect_count = 0

    redirect_domain_change = 0

    redirect_https_downgrade = 0

    form_count = 0

    password_form = 0

    external_resource_ratio = 0.0

    javascript_count = 0

    iframe_count = 0

    suspicious_script = 0

    # ========================================================
    # RETURN EXACTLY 41 FEATURES
    # ========================================================

    features = {

        "url_length": url_length,
        "domain_length": domain_length,
        "path_length": path_length,
        "query_length": query_length,
        "num_dots": num_dots,
        "num_hyphens": num_hyphens,
        "num_digits": num_digits,
        "num_slashes": num_slashes,
        "num_parameters": num_parameters,
        "num_subdomains": num_subdomains,
        "num_special_chars": num_special_chars,
        "is_https": is_https,
        "is_http": is_http,
        "has_ip": has_ip,
        "unusual_port": unusual_port,
        "has_at_symbol": has_at_symbol,
        "suspicious_tld": suspicious_tld,
        "url_shortener": url_shortener,
        "domain_entropy": domain_entropy,
        "domain_age_days": domain_age_days,
        "registration_info": registration_info,
        "suspicious_keywords": suspicious_keywords,
        "brand_impersonation": brand_impersonation,
        "typosquatting": typosquatting,
        "punycode": punycode,
        "homograph": homograph,
        "dns_exists": dns_exists,
        "dns_ip_count": dns_ip_count,
        "dns_private_ip": dns_private_ip,
        "dns_suspicious": dns_suspicious,
        "threat_intelligence": threat_intelligence,
        "historical_reputation": historical_reputation,
        "redirect_count": redirect_count,
        "redirect_domain_change": redirect_domain_change,
        "redirect_https_downgrade": redirect_https_downgrade,
        "form_count": form_count,
        "password_form": password_form,
        "external_resource_ratio": external_resource_ratio,
        "javascript_count": javascript_count,
        "iframe_count": iframe_count,
        "suspicious_script": suspicious_script,
    }

    return features


# ============================================================
# FEATURE VECTOR
# ============================================================

def get_feature_vector(features):
    """
    Convert the dictionary into the exact 41-feature vector
    expected by the RandomForest model.
    """

    if not isinstance(features, dict):
        raise TypeError(
            "features must be a dictionary"
        )

    vector = []

    for feature_name in FEATURE_NAMES:

        value = features.get(
            feature_name,
            0
        )

        try:
            value = float(value)
        except Exception:
            value = 0.0

        if not math.isfinite(value):
            value = 0.0

        vector.append(value)

    if len(vector) != 41:
        raise ValueError(
            f"Feature vector contains {len(vector)} features. "
            f"Expected exactly 41."
        )

    return vector


# ============================================================
# FEATURE NAME HELPER
# ============================================================

def get_feature_names():
    return FEATURE_NAMES.copy()


# ============================================================
# URL INFORMATION HELPER
# ============================================================

def analyze_url_input(url):
    """
    Useful for the Streamlit UI.

    Returns normalized URL, domain, protocol and validity.
    """

    normalized, parsed = parse_url(url)

    domain = ""

    try:
        domain = (parsed.hostname or "").lower().rstrip(".")
    except Exception:
        pass

    return {
        "original_url": str(url).strip(),
        "normalized_url": normalized,
        "domain": domain,
        "scheme": parsed.scheme.lower(),
        "valid": is_valid_url(url),
        "registered_domain": get_registered_domain(domain),
        "is_ip": is_ip_address(domain),
        "is_known_legitimate_domain":
            is_known_legitimate_domain(domain),
    }


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_urls = [
        "google.com",
        "www.google.com",
        "https://google.com",
        "https://www.google.com/",
        "HTTP://GOOGLE.COM",
        "google.com/search?q=test",
        "example.com",
        "www.example.com/login",
        "http://192.0.2.1/@login/verify-account",
        "https://xn--pple-43d.com",
        "https://google-login-example.com/verify",
    ]

    print("=" * 75)
    print("ROBUST URL FEATURE EXTRACTOR TEST")
    print("=" * 75)

    print(
        f"Feature count: {len(FEATURE_NAMES)}"
    )

    for test_url in test_urls:

        print()
        print("-" * 75)
        print(f"INPUT : {test_url}")

        info = analyze_url_input(
            test_url
        )

        print(
            f"NORMAL: {info['normalized_url']}"
        )

        print(
            f"DOMAIN: {info['domain']}"
        )

        print(
            f"ROOT  : {info['registered_domain']}"
        )

        print(
            f"VALID : {info['valid']}"
        )

        print(
            f"HTTPS : {info['scheme'] == 'https'}"
        )

        print(
            f"KNOWN : {info['is_known_legitimate_domain']}"
        )

        features = get_features(
            test_url
        )

        vector = get_feature_vector(
            features
        )

        print(
            f"VECTOR LENGTH: {len(vector)}"
        )

        print(
            f"Typosquatting: "
            f"{features['typosquatting']}"
        )

        print(
            f"Brand impersonation: "
            f"{features['brand_impersonation']}"
        )

        print(
            f"Punycode: "
            f"{features['punycode']}"
        )

        print(
            f"Homograph: "
            f"{features['homograph']}"
        )

    print()
    print("=" * 75)
    print("TEST COMPLETE")
    print("=" * 75)