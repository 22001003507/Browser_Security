from __future__ import annotations

import re
from urllib.parse import urljoin, urlparse

import requests
from bs4 import BeautifulSoup


REQUEST_TIMEOUT = 8

SUSPICIOUS_KEYWORDS = {
    "verify account",
    "verify your account",
    "login",
    "sign in",
    "password",
    "confirm identity",
    "update payment",
    "payment verification",
    "bank account",
    "security alert",
    "urgent",
    "wallet",
    "free bitcoin",
    "claim prize",
}

SUSPICIOUS_JS_PATTERNS = [
    r"eval\s*\(",
    r"atob\s*\(",
    r"document\.write\s*\(",
    r"fromCharCode\s*\(",
    r"unescape\s*\(",
    r"setTimeout\s*\(\s*[\"']",
]


def fetch_page(url: str):
    """
    Download webpage for controlled static inspection.

    This does NOT open the URL in the user's normal browser.
    """

    headers = {
        "User-Agent": (
            "Mozilla/5.0 "
            "(Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 "
            "Chrome/120 Safari/537.36"
        )
    }

    try:
        response = requests.get(
            url,
            headers=headers,
            timeout=REQUEST_TIMEOUT,
            allow_redirects=True,
            stream=True,
        )

        content_type = response.headers.get(
            "Content-Type",
            ""
        ).lower()

        if "text/html" not in content_type:
            return {
                "success": False,
                "error": "Response is not HTML",
            }

        # Limit inspection size.
        raw = response.raw.read(2_000_000, decode_content=True)

        html = raw.decode(
            response.encoding or "utf-8",
            errors="replace",
        )

        return {
            "success": True,
            "html": html,
            "final_url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
        }

    except Exception as exc:
        return {
            "success": False,
            "error": str(exc),
        }


def analyze_html(url: str):
    result = fetch_page(url)

    if not result["success"]:
        return {
            "success": False,
            "risk_points": 0,
            "indicators": [],
            "forms": 0,
            "iframes": 0,
            "scripts": 0,
            "redirected": False,
            "final_url": None,
        }

    html = result["html"]

    soup = BeautifulSoup(
        html,
        "html.parser",
    )

    text = soup.get_text(
        " ",
        strip=True,
    ).lower()

    indicators = []
    risk_points = 0

    # --------------------------------------------------
    # Suspicious keywords
    # --------------------------------------------------

    found_keywords = []

    for keyword in SUSPICIOUS_KEYWORDS:
        if keyword in text:
            found_keywords.append(keyword)

    if found_keywords:
        risk_points += min(
            15,
            len(found_keywords) * 3,
        )

        indicators.append(
            "Suspicious security/login/payment language"
        )

    # --------------------------------------------------
    # Password fields
    # --------------------------------------------------

    password_fields = soup.find_all(
        "input",
        {
            "type": re.compile(
                "^password$",
                re.I,
            )
        },
    )

    if password_fields:
        risk_points += 10

        indicators.append(
            f"Password form detected ({len(password_fields)})"
        )

    # --------------------------------------------------
    # Forms
    # --------------------------------------------------

    forms = soup.find_all("form")

    if len(forms) >= 3:
        risk_points += 5

        indicators.append(
            "Multiple forms detected"
        )

    # --------------------------------------------------
    # Iframes
    # --------------------------------------------------

    iframes = soup.find_all("iframe")

    if len(iframes) >= 3:
        risk_points += 8

        indicators.append(
            "Multiple embedded frames detected"
        )

    # --------------------------------------------------
    # JavaScript
    # --------------------------------------------------

    scripts = soup.find_all("script")

    js_text = "\n".join(
        script.get_text(
            " ",
            strip=False,
        )
        for script in scripts
    )

    suspicious_js = []

    for pattern in SUSPICIOUS_JS_PATTERNS:
        if re.search(
            pattern,
            js_text,
            re.I,
        ):
            suspicious_js.append(pattern)

    if suspicious_js:
        risk_points += min(
            15,
            len(suspicious_js) * 5,
        )

        indicators.append(
            "Potentially obfuscated/suspicious JavaScript"
        )

    # --------------------------------------------------
    # External domains
    # --------------------------------------------------

    base_domain = urlparse(
        result["final_url"] or url
    ).netloc.lower()

    external_domains = set()

    for tag in soup.find_all(
        ["script", "iframe", "img", "link", "form"]
    ):
        value = (
            tag.get("src")
            or tag.get("href")
            or tag.get("action")
        )

        if not value:
            continue

        try:
            absolute = urljoin(
                result["final_url"] or url,
                value,
            )

            parsed = urlparse(absolute)

            if (
                parsed.netloc
                and parsed.netloc.lower() != base_domain
            ):
                external_domains.add(
                    parsed.netloc.lower()
                )

        except Exception:
            continue

    if len(external_domains) >= 10:
        risk_points += 7

        indicators.append(
            "Large number of external domains"
        )

    # --------------------------------------------------
    # Redirect
    # --------------------------------------------------

    redirected = (
        result["final_url"]
        and result["final_url"] != url
    )

    if redirected:
        risk_points += 8

        indicators.append(
            "HTTP redirect detected"
        )

    return {
        "success": True,
        "risk_points": min(
            risk_points,
            50,
        ),
        "indicators": indicators,
        "forms": len(forms),
        "password_fields": len(password_fields),
        "iframes": len(iframes),
        "scripts": len(scripts),
        "external_domains": len(external_domains),
        "redirected": redirected,
        "final_url": result["final_url"],
        "status_code": result["status_code"],
    }