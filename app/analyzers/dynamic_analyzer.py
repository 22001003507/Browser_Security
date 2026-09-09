from urllib.parse import urlparse, urljoin
import re
import json
import html as html_module


try:
    import requests
except ImportError:
    requests = None


try:
    from bs4 import BeautifulSoup
except ImportError:
    BeautifulSoup = None


# ============================================================
# VM HEADLESS SCANNER
# ============================================================

try:
    from app.vm_launcher import scan_url_in_vm

    VM_SCAN_AVAILABLE = True

except Exception:
    scan_url_in_vm = None
    VM_SCAN_AVAILABLE = False


# ============================================================
# SUSPICIOUS JAVASCRIPT
# ============================================================

SUSPICIOUS_JS_PATTERNS = [

    r"\beval\s*\(",

    r"\batob\s*\(",

    r"\bunescape\s*\(",

    r"String\.fromCharCode",

    r"document\.write\s*\(",

    r"window\.location",

    r"location\.href",

    r"location\.replace",

    r"location\.assign",

    r"document\.cookie",

    r"localStorage",

    r"sessionStorage",

    r"fetch\s*\(",

    r"XMLHttpRequest",

    r"WebSocket",

    r"crypto",

    r"base64",

    r"powershell",

    r"cmd\.exe",

]


# ============================================================
# SUSPICIOUS PAGE KEYWORDS
# ============================================================

SUSPICIOUS_PAGE_KEYWORDS = [

    "verify your account",

    "verify account",

    "confirm your account",

    "login",

    "sign in",

    "password",

    "bank account",

    "credit card",

    "debit card",

    "payment",

    "billing",

    "security verification",

    "account suspended",

    "account locked",

    "urgent action",

    "update payment",

    "wallet",

    "crypto",

    "otp",

    "one time password",

]


# ============================================================
# SAFE HTTP FETCH
# ============================================================

def fetch_url(
    url,
    timeout=10
):

    if requests is None:

        return (
            None,
            "requests is not installed."
        )

    try:

        response = requests.get(
            url,
            timeout=timeout,
            allow_redirects=True,
            headers={
                "User-Agent":
                    "Mozilla/5.0 "
                    "(Windows NT 10.0; Win64; x64) "
                    "AppleWebKit/537.36 "
                    "(KHTML, like Gecko) "
                    "Chrome/131 Safari/537.36"
            },
        )

        return response, None

    except Exception as exc:

        return (
            None,
            str(exc)
        )


# ============================================================
# DOMAIN
# ============================================================

def domain_from_url(url):

    try:

        return (
            urlparse(url).hostname
            or ""
        ).lower()

    except Exception:

        return ""


# ============================================================
# REDIRECT ANALYSIS
# ============================================================

def analyze_redirects(response):

    if response is None:
        return []

    redirects = []

    try:

        for item in response.history:

            redirects.append({
                "status_code":
                    item.status_code,

                "url":
                    item.url,

                "location":
                    item.headers.get(
                        "Location",
                        ""
                    ),
            })

    except Exception:
        pass

    return redirects


# ============================================================
# DOWNLOAD DETECTION
# ============================================================

def detect_downloads(response):

    if response is None:
        return []

    try:

        content_type = (
            response.headers
            .get(
                "Content-Type",
                ""
            )
            .lower()
        )

        disposition = (
            response.headers
            .get(
                "Content-Disposition",
                ""
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

        url_lower = response.url.lower()

        extension_match = any(
            url_lower.endswith(ext)
            for ext in download_extensions
        )

        attachment_match = (
            "attachment"
            in disposition
        )

        binary_match = any(
            value in content_type
            for value in (
                "application/octet-stream",
                "application/x-msdownload",
                "application/zip",
                "application/x-rar",
            )
        )

        if (
            extension_match
            or attachment_match
            or binary_match
        ):

            return [{
                "url": response.url,
                "content_type": content_type,
            }]

    except Exception:
        pass

    return []


# ============================================================
# JAVASCRIPT ANALYSIS
# ============================================================

def analyze_javascript(
    soup
):

    scripts = soup.find_all(
        "script"
    )

    suspicious = 0

    external_scripts = 0

    for script in scripts[:500]:

        src = script.get(
            "src",
            ""
        )

        if src:
            external_scripts += 1

        text = script.get_text(
            " ",
            strip=True
        )

        combined = (
            src + " " + text
        ).lower()

        for pattern in SUSPICIOUS_JS_PATTERNS:

            try:

                if re.search(
                    pattern,
                    combined,
                    re.IGNORECASE
                ):

                    suspicious += 1

                    break

            except Exception:
                continue

    return {
        "javascript_count":
            len(scripts),

        "suspicious_javascript":
            suspicious,

        "external_scripts":
            external_scripts,
    }


# ============================================================
# PAGE CONTENT ANALYSIS
# ============================================================

def analyze_html(
    html,
    page_url
):

    result = {

        "html_available": 1,

        "title": "",

        "text_length": 0,

        "login_keywords": 0,

        "suspicious_keywords": 0,

        "form_count": 0,

        "password_forms": 0,

        "iframe_count": 0,

        "external_resource_count": 0,

        "external_resource_ratio": 0.0,

        "javascript_count": 0,

        "suspicious_javascript": 0,

        "external_scripts": 0,

        "hidden_elements": 0,

        "cross_domain_forms": 0,

        "forms": [],

        "iframes": [],

    }

    if not html:
        return result

    if BeautifulSoup is None:
        return result

    try:

        soup = BeautifulSoup(
            html,
            "html.parser"
        )

    except Exception:

        return result

    # --------------------------------------------------------
    # TITLE
    # --------------------------------------------------------

    title = soup.title

    if title:

        result["title"] = (
            title.get_text(
                " ",
                strip=True
            )[:300]
        )

    # --------------------------------------------------------
    # TEXT
    # --------------------------------------------------------

    text = soup.get_text(
        " ",
        strip=True
    )

    text_lower = text.lower()

    result["text_length"] = len(text)

    # --------------------------------------------------------
    # KEYWORDS
    # --------------------------------------------------------

    result["login_keywords"] = sum(
        1
        for word in (
            "login",
            "sign in",
            "signin",
            "log in",
            "password",
        )
        if word in text_lower
    )

    result["suspicious_keywords"] = sum(
        1
        for word in SUSPICIOUS_PAGE_KEYWORDS
        if word in text_lower
    )

    # --------------------------------------------------------
    # FORMS
    # --------------------------------------------------------

    forms = soup.find_all(
        "form"
    )

    result["form_count"] = len(forms)

    page_domain = domain_from_url(
        page_url
    )

    for form in forms[:100]:

        action = form.get(
            "action",
            ""
        )

        action_url = urljoin(
            page_url,
            action
        )

        action_domain = domain_from_url(
            action_url
        )

        password_inputs = form.find_all(
            "input",
            {
                "type":
                    re.compile(
                        r"^password$",
                        re.IGNORECASE
                    )
            }
        )

        if password_inputs:

            result[
                "password_forms"
            ] += 1

        if (
            action_domain
            and page_domain
            and action_domain != page_domain
        ):

            result[
                "cross_domain_forms"
            ] += 1

        result["forms"].append({
            "action": action,
            "method":
                form.get(
                    "method",
                    "get"
                ),
            "password":
                bool(password_inputs),
        })

    # --------------------------------------------------------
    # IFRAMES
    # --------------------------------------------------------

    iframes = soup.find_all(
        "iframe"
    )

    result["iframe_count"] = (
        len(iframes)
    )

    for iframe in iframes[:100]:

        result["iframes"].append(
            iframe.get(
                "src",
                ""
            )
        )

    # --------------------------------------------------------
    # JAVASCRIPT
    # --------------------------------------------------------

    result.update(
        analyze_javascript(
            soup
        )
    )

    # --------------------------------------------------------
    # HIDDEN ELEMENTS
    # --------------------------------------------------------

    hidden = 0

    for element in soup.find_all(
        True
    ):

        style = (
            element.get(
                "style",
                ""
            )
            .lower()
        )

        if (
            element.has_attr(
                "hidden"
            )
            or "display:none"
            in style
            or "visibility:hidden"
            in style
        ):

            hidden += 1

    result[
        "hidden_elements"
    ] = hidden

    # --------------------------------------------------------
    # EXTERNAL RESOURCES
    # --------------------------------------------------------

    resources = []

    for tag in soup.find_all(
        ["script", "img", "iframe", "link", "source"]
    ):

        for attr in (
            "src",
            "href"
        ):

            value = tag.get(
                attr,
                ""
            )

            if value:
                resources.append(
                    urljoin(
                        page_url,
                        value
                    )
                )

    external = 0

    for resource in resources:

        resource_domain = (
            domain_from_url(
                resource
            )
        )

        if (
            resource_domain
            and page_domain
            and resource_domain
            != page_domain
        ):

            external += 1

    result[
        "external_resource_count"
    ] = external

    if resources:

        result[
            "external_resource_ratio"
        ] = (
            external /
            len(resources)
        )

    return result


# ============================================================
# LOCAL HTTP ANALYSIS
# ============================================================

def analyze_http_url(
    url,
    timeout=10
):

    result = {

        "success": False,

        "url": url,

        "final_url": url,

        "status_code": None,

        "content_type": "",

        "redirect_count": 0,

        "redirect_domain_change": 0,

        "redirect_https_downgrade": 0,

        "download_count": 0,

        "downloads": [],

        "error": "",

    }

    response, error = fetch_url(
        url,
        timeout
    )

    if response is None:

        result["error"] = (
            error
            or "Unable to fetch URL."
        )

        return result

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
            ""
        )
    )

    redirects = analyze_redirects(
        response
    )

    result[
        "redirect_count"
    ] = len(redirects)

    domains = []

    for item in redirects:

        domain = domain_from_url(
            item.get(
                "url",
                ""
            )
        )

        if domain:
            domains.append(domain)

    final_domain = domain_from_url(
        response.url
    )

    if final_domain:
        domains.append(final_domain)

    if len(set(domains)) > 1:

        result[
            "redirect_domain_change"
        ] = 1

    original_scheme = (
        urlparse(url)
        .scheme
        .lower()
    )

    final_scheme = (
        urlparse(response.url)
        .scheme
        .lower()
    )

    if (
        original_scheme == "https"
        and final_scheme == "http"
    ):

        result[
            "redirect_https_downgrade"
        ] = 1

    downloads = detect_downloads(
        response
    )

    result["downloads"] = downloads

    result[
        "download_count"
    ] = len(downloads)

    if (
        "text/html"
        in result[
            "content_type"
        ].lower()
    ):

        result.update(
            analyze_html(
                response.text,
                response.url
            )
        )

    return result


# ============================================================
# FINAL DYNAMIC ANALYSIS
# ============================================================

def analyze_dynamic_url(
    url,
    timeout=12
):

    http_result = analyze_http_url(
        url,
        timeout=timeout
    )

    # --------------------------------------------------------
    # VM RENDERED SCAN
    # --------------------------------------------------------

    vm_result = {

        "available": False,

        "success": False,

        "error": (
            "Kali VM headless scanner "
            "not available."
        ),

    }

    if VM_SCAN_AVAILABLE:

        try:

            vm_result = scan_url_in_vm(
                url,
                timeout=45
            )

        except Exception as exc:

            vm_result = {
                "available": True,
                "success": False,
                "error": str(exc),
            }

    # --------------------------------------------------------
    # Combine
    # --------------------------------------------------------

    combined = dict(
        http_result
    )

    combined[
        "vm_scan"
    ] = vm_result

    combined[
        "inside_scan"
    ] = bool(
        vm_result.get(
            "success",
            False
        )
    )

    # Prefer rendered page when available.
    rendered_html = (
        vm_result.get(
            "html",
            ""
        )
    )

    if rendered_html:

        rendered_result = (
            analyze_html(
                rendered_html,
                vm_result.get(
                    "final_url",
                    url
                )
            )
        )

        combined[
            "rendered"
        ] = rendered_result

    else:

        combined[
            "rendered"
        ] = {}

    return combined