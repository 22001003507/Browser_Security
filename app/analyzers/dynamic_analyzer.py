from urllib.parse import urlparse
import re


# ============================================================
# DYNAMIC ANALYZER
# ============================================================
#
# This module performs lightweight HTTP/HTML analysis.
#
# It does NOT open the URL in your normal Windows browser.
#
# The actual risky-site browser isolation is handled separately
# by app/vm_launcher.py and opens the URL inside Kali Linux VM.
#
# ============================================================


try:
    import requests
except ImportError:
    requests = None

try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# ============================================================
# SUSPICIOUS JAVASCRIPT PATTERNS
# ============================================================

SUSPICIOUS_JS_PATTERNS = [
    r"eval\s*\(",
    r"document\.write\s*\(",
    r"window\.location",
    r"location\.href",
    r"location\.replace",
    r"atob\s*\(",
    r"fromCharCode\s*\(",
    r"unescape\s*\(",
    r"base64",
    r"crypto",
    r"download",
    r"powershell",
    r"cmd\.exe",
    r"shell",
]


# ============================================================
# SAFE REQUEST
# ============================================================

def fetch_url(url, timeout=8):
    """
    Fetch a URL using a normal HTTP request.

    This is only for lightweight analysis.
    It does not launch Chrome.
    """

    if requests is None:
        return None, "requests package is not installed"

    try:

        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "Chrome/120 Safari/537.36"
                )
            },
        )

        return response, None

    except Exception as exc:

        return None, str(exc)


# ============================================================
# REDIRECT ANALYSIS
# ============================================================

def analyze_redirects(response):

    redirects = []

    if response is None:
        return redirects

    try:

        for item in response.history:

            redirects.append(
                {
                    "status_code": item.status_code,
                    "url": item.url,
                    "location": item.headers.get(
                        "Location",
                        "",
                    ),
                }
            )

        return redirects

    except Exception:
        return redirects


# ============================================================
# DOMAIN COMPARISON
# ============================================================

def domain_from_url(url):

    try:
        return (
            urlparse(url).hostname
            or ""
        ).lower()

    except Exception:
        return ""


def analyze_redirect_domains(response):

    redirects = analyze_redirects(
        response
    )

    domains = []

    for redirect in redirects:

        domain = domain_from_url(
            redirect.get("url", "")
        )

        if domain:
            domains.append(domain)

    if response is not None:

        final_domain = domain_from_url(
            response.url
        )

        if final_domain:
            domains.append(final_domain)

    unique_domains = list(
        dict.fromkeys(domains)
    )

    return unique_domains


# ============================================================
# HTTPS DOWNGRADE
# ============================================================

def detect_https_downgrade(response):

    if response is None:
        return 0

    try:

        original = response.request.url

        final = response.url

        original_scheme = (
            urlparse(original)
            .scheme
            .lower()
        )

        final_scheme = (
            urlparse(final)
            .scheme
            .lower()
        )

        if (
            original_scheme == "https"
            and final_scheme == "http"
        ):
            return 1

    except Exception:
        pass

    return 0


# ============================================================
# HTML ANALYSIS
# ============================================================

def analyze_html(html, page_url):

    result = {
        "iframe_count": 0,
        "form_count": 0,
        "password_forms": 0,
        "javascript_count": 0,
        "suspicious_javascript": 0,
        "external_resource_ratio": 0.0,
        "forms": [],
        "iframes": [],
    }

    if not html:
        return result

    # --------------------------------------------------------
    # BeautifulSoup
    # --------------------------------------------------------

    if BeautifulSoup is None:
        return result

    try:

        soup = BeautifulSoup(
            html,
            "html.parser",
        )

    except Exception:
        return result

    # ========================================================
    # IFRAME
    # ========================================================

    iframes = soup.find_all(
        "iframe"
    )

    result["iframe_count"] = len(
        iframes
    )

    for iframe in iframes[:50]:

        result["iframes"].append(
            iframe.get("src", "")
        )

    # ========================================================
    # FORMS
    # ========================================================

    forms = soup.find_all(
        "form"
    )

    result["form_count"] = len(
        forms
    )

    for form in forms[:50]:

        action = form.get(
            "action",
            "",
        )

        method = form.get(
            "method",
            "get",
        )

        result["forms"].append(
            {
                "action": action,
                "method": method,
            }
        )

        password_inputs = form.find_all(
            "input",
            {
                "type": re.compile(
                    r"^password$",
                    re.IGNORECASE,
                )
            },
        )

        if password_inputs:

            result["password_forms"] += 1

    # ========================================================
    # JAVASCRIPT
    # ========================================================

    scripts = soup.find_all(
        "script"
    )

    result["javascript_count"] = len(
        scripts
    )

    suspicious_count = 0

    for script in scripts[:200]:

        script_text = script.get_text(
            " ",
            strip=True,
        )

        src = script.get(
            "src",
            "",
        )

        combined = (
            f"{src} {script_text}"
        ).lower()

        for pattern in SUSPICIOUS_JS_PATTERNS:

            try:

                if re.search(
                    pattern,
                    combined,
                    re.IGNORECASE,
                ):

                    suspicious_count += 1

                    break

            except Exception:
                continue

    result[
        "suspicious_javascript"
    ] = suspicious_count

    # ========================================================
    # EXTERNAL RESOURCES
    # ========================================================

    page_domain = domain_from_url(
        page_url
    )

    resources = []

    # Images
    for tag in soup.find_all(
        "img"
    ):

        src = tag.get(
            "src",
            "",
        )

        if src:
            resources.append(src)

    # Scripts
    for tag in soup.find_all(
        "script"
    ):

        src = tag.get(
            "src",
            "",
        )

        if src:
            resources.append(src)

    # Links
    for tag in soup.find_all(
        "link"
    ):

        href = tag.get(
            "href",
            "",
        )

        if href:
            resources.append(href)

    # Stylesheets
    for tag in soup.find_all(
        "source"
    ):

        src = tag.get(
            "src",
            "",
        )

        if src:
            resources.append(src)

    if resources:

        external = 0

        for resource in resources:

            try:

                parsed = urlparse(
                    resource
                )

                resource_domain = (
                    parsed.hostname
                    or ""
                ).lower()

                if (
                    resource_domain
                    and resource_domain != page_domain
                ):

                    external += 1

            except Exception:
                continue

        result[
            "external_resource_ratio"
        ] = (
            external / len(resources)
        )

    return result


# ============================================================
# DOWNLOAD DETECTION
# ============================================================

def detect_downloads(response):

    downloads = []

    if response is None:
        return downloads

    try:

        content_type = (
            response.headers
            .get(
                "Content-Type",
                "",
            )
            .lower()
        )

        content_disposition = (
            response.headers
            .get(
                "Content-Disposition",
                "",
            )
            .lower()
        )

        download_extensions = (
            ".exe",
            ".msi",
            ".dll",
            ".bat",
            ".cmd",
            ".ps1",
            ".scr",
            ".zip",
            ".rar",
            ".7z",
            ".apk",
            ".dmg",
            ".pkg",
        )

        url_lower = (
            response.url.lower()
        )

        extension_match = any(
            url_lower.endswith(ext)
            for ext in download_extensions
        )

        disposition_match = (
            "attachment"
            in content_disposition
        )

        binary_match = any(
            x in content_type
            for x in [
                "application/octet-stream",
                "application/x-msdownload",
                "application/zip",
                "application/x-rar",
            ]
        )

        if (
            extension_match
            or disposition_match
            or binary_match
        ):

            downloads.append(
                {
                    "url": response.url,
                    "content_type": content_type,
                }
            )

    except Exception:
        pass

    return downloads


# ============================================================
# MAIN DYNAMIC ANALYZER
# ============================================================

def analyze_dynamic_url(
    url,
    timeout=8,
):

    result = {
        "success": False,
        "url": url,
        "final_url": url,

        "error": "",

        "redirects": [],
        "redirect_count": 0,

        "redirect_domains": [],
        "redirect_domain_change": 0,

        "redirect_https_downgrade": 0,

        "downloads": [],
        "download_count": 0,

        "iframes": [],
        "iframe_count": 0,

        "forms": [],
        "form_count": 0,

        "password_forms": 0,

        "javascript_count": 0,

        "suspicious_javascript": 0,

        "external_resource_ratio": 0.0,

        "status_code": None,
        "content_type": "",
    }

    # --------------------------------------------------------
    # Empty URL
    # --------------------------------------------------------

    if not url:

        result["error"] = (
            "URL is empty"
        )

        return result

    # --------------------------------------------------------
    # Fetch
    # --------------------------------------------------------

    response, error = fetch_url(
        url,
        timeout=timeout,
    )

    if response is None:

        result["error"] = (
            error
            or "Unable to fetch URL"
        )

        return result

    # --------------------------------------------------------
    # Basic response information
    # --------------------------------------------------------

    result["success"] = True

    result["final_url"] = (
        response.url
    )

    result["status_code"] = (
        response.status_code
    )

    result["content_type"] = (
        response.headers
        .get(
            "Content-Type",
            "",
        )
    )

    # --------------------------------------------------------
    # Redirects
    # --------------------------------------------------------

    redirects = analyze_redirects(
        response
    )

    result["redirects"] = redirects

    result["redirect_count"] = len(
        redirects
    )

    # --------------------------------------------------------
    # Redirect domains
    # --------------------------------------------------------

    redirect_domains = (
        analyze_redirect_domains(
            response
        )
    )

    result[
        "redirect_domains"
    ] = redirect_domains

    if len(redirect_domains) > 1:

        result[
            "redirect_domain_change"
        ] = 1

    # --------------------------------------------------------
    # HTTPS downgrade
    # --------------------------------------------------------

    result[
        "redirect_https_downgrade"
    ] = detect_https_downgrade(
        response
    )

    # --------------------------------------------------------
    # Downloads
    # --------------------------------------------------------

    downloads = detect_downloads(
        response
    )

    result["downloads"] = downloads

    result["download_count"] = len(
        downloads
    )

    # --------------------------------------------------------
    # HTML
    # --------------------------------------------------------

    content_type = (
        result["content_type"]
        .lower()
    )

    if (
        "text/html"
        in content_type
    ):

        try:

            html_result = analyze_html(
                response.text,
                response.url,
            )

            result.update(
                html_result
            )

        except Exception as exc:

            result["error"] = (
                f"HTML analysis error: {exc}"
            )

    return result


# ============================================================
# COMPATIBILITY ALIAS
# ============================================================

def analyze_url_dynamic(
    url,
    timeout=8,
):
    return analyze_dynamic_url(
        url,
        timeout=timeout,
    )


# ============================================================
# TEST
# ============================================================

if __name__ == "__main__":

    test_url = "https://example.com"

    print("=" * 70)
    print("DYNAMIC URL ANALYZER TEST")
    print("=" * 70)

    print(
        f"URL: {test_url}"
    )

    result = analyze_dynamic_url(
        test_url
    )

    print()

    print(
        f"Success: "
        f"{result['success']}"
    )

    print(
        f"Status: "
        f"{result['status_code']}"
    )

    print(
        f"Final URL: "
        f"{result['final_url']}"
    )

    print(
        f"Redirects: "
        f"{result['redirect_count']}"
    )

    print(
        f"Downloads: "
        f"{result['download_count']}"
    )

    print(
        f"IFrames: "
        f"{result['iframe_count']}"
    )

    print(
        f"Forms: "
        f"{result['form_count']}"
    )

    print(
        f"Password forms: "
        f"{result['password_forms']}"
    )

    print(
        f"JavaScript: "
        f"{result['javascript_count']}"
    )

    print(
        f"Suspicious JavaScript: "
        f"{result['suspicious_javascript']}"
    )

    print()

    if result["error"]:
        print(
            f"Error: {result['error']}"
        )

    print("=" * 70)