from pathlib import Path
import sys
import os
import webbrowser

import joblib
import streamlit as st


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT.parent) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT.parent))


# ============================================================
# IMPORTS
# ============================================================

from app.features.url_features import (
    get_features,
    get_feature_vector,
    FEATURE_NAMES,
    normalize_url,
)

from app.analyzers.dynamic_analyzer import (
    analyze_dynamic_url,
)


# ============================================================
# VM IMPORTS
# ============================================================

LOCAL_WINDOWS_MODE = os.name == "nt"

if LOCAL_WINDOWS_MODE:

    try:

        from app.vm_launcher import (
            vm_available,
            chrome_available,
            get_vm_info,
            open_url_in_vm,
            start_kali_vm,
        )

        VM_AVAILABLE = True

    except Exception:

        VM_AVAILABLE = False

        def vm_available():
            return False

        def chrome_available():
            return False

        def get_vm_info():
            return {
                "available": False,
                "message": "VM launcher could not be imported.",
            }

        def open_url_in_vm(url):
            return {
                "success": False,
                "message": "VM launcher is unavailable.",
            }

        def start_kali_vm():
            return {
                "success": False,
                "message": "VM launcher is unavailable.",
            }

else:

    VM_AVAILABLE = False

    def vm_available():
        return False

    def chrome_available():
        return False

    def get_vm_info():
        return {
            "available": False,
            "message": "VM integration is local only.",
        }

    def open_url_in_vm(url):
        return {
            "success": False,
            "message": "VM integration is unavailable in cloud mode.",
        }

    def start_kali_vm():
        return {
            "success": False,
            "message": "VM integration is unavailable in cloud mode.",
        }


# ============================================================
# PAGE
# ============================================================

st.set_page_config(
    page_title="AI Browser Security",
    page_icon="🛡️",
    layout="wide",
)

st.title("🛡️ AI Browser Security")

st.caption(
    "Multi-Signal AI Malicious Website Detection "
    "with Adaptive VM Isolation"
)


# ============================================================
# MODEL
# ============================================================

MODEL_PATH = (
    PROJECT_ROOT
    / "models"
    / "url_risk_ensemble.joblib"
)


@st.cache_resource
def load_model():

    if not MODEL_PATH.exists():

        return (
            None,
            "Ensemble model not found.",
        )

    try:

        bundle = joblib.load(MODEL_PATH)

        if isinstance(bundle, dict):

            model = bundle["model"]

        else:

            model = bundle

        return (
            model,
            None,
        )

    except Exception as exc:

        return (
            None,
            str(exc),
        )


model, model_error = load_model()


# ============================================================
# MODEL VALIDATION
# ============================================================

if model is None:

    st.error(
        "❌ ML model is not available."
    )

    st.code(
        "python -m app.ml.train_model"
    )

    st.error(model_error)

    st.stop()


MODEL_FEATURE_COUNT = getattr(
    model,
    "n_features_in_",
    None,
)


if (
    MODEL_FEATURE_COUNT is not None
    and MODEL_FEATURE_COUNT != len(FEATURE_NAMES)
):

    st.error(
        "❌ Model/feature mismatch."
    )

    st.write(
        f"Model expects: {MODEL_FEATURE_COUNT}"
    )

    st.write(
        f"Application provides: {len(FEATURE_NAMES)}"
    )

    st.stop()


# ============================================================
# HELPERS
# ============================================================

def clamp(
    value,
    minimum=0,
    maximum=100,
):

    return max(
        minimum,
        min(
            maximum,
            float(value),
        ),
    )


def prepare_url(value):

    value = str(
        value or ""
    ).strip()

    if not value:
        return None

    try:

        value = normalize_url(value)

    except Exception:

        if not value.lower().startswith(
            (
                "http://",
                "https://",
            )
        ):

            value = (
                "https://"
                + value
            )

    return value


# ============================================================
# ML PREDICTION
# ============================================================

def predict_ml(feature_vector):

    probabilities = (
        model.predict_proba(
            [feature_vector]
        )[0]
    )

    classes = getattr(
        model,
        "classes_",
        [0, 1],
    )

    malicious_index = None

    for index, cls in enumerate(classes):

        try:

            if int(cls) == 1:

                malicious_index = index
                break

        except Exception:

            pass

    if malicious_index is None:

        malicious_index = (
            len(probabilities) - 1
        )

    return float(
        probabilities[
            malicious_index
        ]
    )


# ============================================================
# URL RULE SCORE
# ============================================================

def rule_score(features):

    score = 0
    reasons = []

    rules = [

        (
            "has_ip",
            20,
            "IP address used instead of a normal domain.",
        ),

        (
            "has_at_symbol",
            25,
            "URL contains '@' and may disguise the destination.",
        ),

        (
            "punycode",
            25,
            "Punycode detected.",
        ),

        (
            "homograph",
            35,
            "Possible homograph attack detected.",
        ),

        (
            "brand_impersonation",
            30,
            "Possible brand impersonation detected.",
        ),

        (
            "typosquatting",
            25,
            "Possible typosquatting detected.",
        ),

        (
            "suspicious_keywords",
            15,
            "Suspicious URL keywords detected.",
        ),

        (
            "suspicious_tld",
            10,
            "Suspicious TLD detected.",
        ),

        (
            "url_shortener",
            10,
            "URL shortener detected.",
        ),

        (
            "unusual_port",
            12,
            "Unusual network port detected.",
        ),

        (
            "is_http",
            8,
            "Website uses HTTP instead of HTTPS.",
        ),

        (
            "dns_private_ip",
            20,
            "Domain resolves to a private IP.",
        ),
    ]

    for feature, points, reason in rules:

        if features.get(
            feature,
            0,
        ):

            score += points

            reasons.append(reason)

    if features.get(
        "url_length",
        0,
    ) >= 150:

        score += 8

        reasons.append(
            "URL is unusually long."
        )

    if features.get(
        "num_subdomains",
        0,
    ) >= 4:

        score += 8

        reasons.append(
            "Many subdomains detected."
        )

    if features.get(
        "num_parameters",
        0,
    ) >= 6:

        score += 8

        reasons.append(
            "Many URL parameters detected."
        )

    return (
        clamp(score),
        reasons,
    )


# ============================================================
# CONTENT RISK
# ============================================================

def content_risk(dynamic):

    if not dynamic:
        return 0, []

    score = 0
    reasons = []

    rendered = dynamic.get(
        "rendered",
        {},
    )

    data = rendered or dynamic

    password_forms = data.get(
        "password_forms",
        0,
    )

    suspicious_js = data.get(
        "suspicious_javascript",
        0,
    )

    suspicious_keywords = data.get(
        "suspicious_keywords",
        0,
    )

    cross_domain_forms = data.get(
        "cross_domain_forms",
        0,
    )

    iframe_count = data.get(
        "iframe_count",
        0,
    )

    hidden_elements = data.get(
        "hidden_elements",
        0,
    )

    external_ratio = data.get(
        "external_resource_ratio",
        0.0,
    )

    form_count = data.get(
        "form_count",
        0,
    )

    redirect_count = dynamic.get(
        "redirect_count",
        0,
    )

    download_count = dynamic.get(
        "download_count",
        0,
    )

    # --------------------------------------------------------
    # Password forms
    # --------------------------------------------------------

    if password_forms:

        score += 18

        reasons.append(
            f"{password_forms} password/login form(s) detected."
        )

    # --------------------------------------------------------
    # Suspicious JavaScript
    # --------------------------------------------------------

    if suspicious_js:

        score += min(
            25,
            suspicious_js * 5,
        )

        reasons.append(
            f"{suspicious_js} suspicious JavaScript pattern(s) detected."
        )

    # --------------------------------------------------------
    # Suspicious content
    # --------------------------------------------------------

    if suspicious_keywords:

        score += min(
            20,
            suspicious_keywords * 4,
        )

        reasons.append(
            "Suspicious account/payment/security language found in page content."
        )

    # --------------------------------------------------------
    # Cross-domain forms
    # --------------------------------------------------------

    if cross_domain_forms:

        score += 25

        reasons.append(
            "Form submits data to another domain."
        )

    # --------------------------------------------------------
    # Redirects
    # --------------------------------------------------------

    if redirect_count >= 3:

        score += 15

        reasons.append(
            f"Multiple redirects detected ({redirect_count})."
        )

    # --------------------------------------------------------
    # Downloads
    # --------------------------------------------------------

    if download_count:

        score += 30

        reasons.append(
            "Potential file download detected."
        )

    # --------------------------------------------------------
    # Iframes
    # --------------------------------------------------------

    if iframe_count >= 5:

        score += 8

        reasons.append(
            "Large number of iframes detected."
        )

    # --------------------------------------------------------
    # Hidden elements
    # --------------------------------------------------------

    if hidden_elements >= 10:

        score += 8

        reasons.append(
            "Many hidden page elements detected."
        )

    # --------------------------------------------------------
    # External resources
    # --------------------------------------------------------

    if external_ratio >= 0.70:

        score += 8

        reasons.append(
            "Large proportion of external resources detected."
        )

    # --------------------------------------------------------
    # Multiple forms
    # --------------------------------------------------------

    if form_count >= 5:

        score += 5

        reasons.append(
            "Multiple forms detected."
        )

    return (
        clamp(score),
        reasons,
    )


# ============================================================
# FINAL RISK
# ============================================================

def calculate_final_risk(
    ml_score,
    url_rule_score,
    content_score,
):

    final = (
        ml_score * 0.55
        +
        url_rule_score * 0.20
        +
        content_score * 0.25
    )

    return clamp(final)


# ============================================================
# RISK LEVEL
#
# IMPORTANT:
#
# 0  - 24  = SAFE
# 25 - 49  = SUSPICIOUS
# 50 - 74  = HIGH RISK
# 75 - 100 = CRITICAL
#
# Every score >= 25 goes to VM.
# ============================================================

def risk_level(score):

    if score >= 75:

        return (
            "CRITICAL",
            "🔴",
        )

    if score >= 50:

        return (
            "HIGH RISK",
            "🟠",
        )

    if score >= 25:

        return (
            "SUSPICIOUS",
            "🟡",
        )

    return (
        "SAFE",
        "🟢",
    )


# ============================================================
# SECURITY DECISION
#
# THIS IS THE MAIN SECURITY RULE.
#
# SAFE:
#     Normal Windows browser
#
# SUSPICIOUS:
#     Kali VM Chrome
#
# HIGH RISK:
#     Kali VM Chrome
#
# CRITICAL:
#     Kali VM Chrome
#
# NEVER FALL BACK TO NORMAL BROWSER
# WHEN VM IS UNAVAILABLE.
# ============================================================

def get_browser_decision(score):

    if score < 25:

        return {
            "level": "SAFE",
            "browser": "NORMAL_BROWSER",
            "isolated": False,
        }

    if score < 50:

        return {
            "level": "SUSPICIOUS",
            "browser": "VM_CHROME",
            "isolated": True,
        }

    if score < 75:

        return {
            "level": "HIGH RISK",
            "browser": "VM_CHROME",
            "isolated": True,
        }

    return {
        "level": "CRITICAL",
        "browser": "VM_CHROME",
        "isolated": True,
    }


# ============================================================
# OPEN SAFE WEBSITE
# ============================================================

def open_in_normal_browser(url):

    try:

        success = webbrowser.open_new_tab(
            url
        )

        if success:

            st.success(
                "🌐 Safe website opened in the normal Windows browser."
            )

        else:

            st.error(
                "❌ Windows could not open the normal browser."
            )

    except Exception as exc:

        st.error(
            f"❌ Failed to open normal browser: {exc}"
        )


# ============================================================
# OPEN SUSPICIOUS/HIGH/CRITICAL WEBSITE IN VM
# ============================================================

def open_in_kali_vm(url):

    # --------------------------------------------------------
    # VM is only possible from Windows host
    # --------------------------------------------------------

    if not LOCAL_WINDOWS_MODE:

        st.error(
            "❌ Kali VM integration is available only "
            "when the Streamlit application runs on Windows."
        )

        return False

    # --------------------------------------------------------
    # Check VM
    # --------------------------------------------------------

    if not vm_available():

        st.warning(
            "🖥️ Kali VM is not currently reachable. "
            "Trying to start the VM..."
        )

        try:

            start_result = start_kali_vm()

        except Exception as exc:

            st.error(
                f"❌ Failed to start Kali VM: {exc}"
            )

            st.error(
                "🔒 Website remains blocked. "
                "It will NOT be opened in the normal browser."
            )

            return False

        if not start_result.get(
            "success",
            False,
        ):

            st.error(
                "❌ Could not start Kali Linux VM."
            )

            st.write(
                start_result.get(
                    "message",
                    "Unknown VM startup error.",
                )
            )

            st.error(
                "🔒 Website remains blocked. "
                "It will NOT be opened in the normal browser."
            )

            return False

        st.success(
            "✅ Kali Linux VM is ready."
        )

    # --------------------------------------------------------
    # Check Chrome
    # --------------------------------------------------------

    if not chrome_available():

        st.error(
            "❌ Google Chrome/Chromium was not detected "
            "inside the Kali Linux VM."
        )

        st.error(
            "🔒 Website remains blocked. "
            "It will NOT be opened in the normal browser."
        )

        return False

    # --------------------------------------------------------
    # Open URL inside VM
    # --------------------------------------------------------

    with st.spinner(
        "🛡️ Opening website inside Kali Linux Chrome..."
    ):

        try:

            result = open_url_in_vm(
                url
            )

        except Exception as exc:

            st.error(
                f"❌ VM launch exception: {exc}"
            )

            st.error(
                "🔒 Website remains blocked. "
                "It will NOT be opened in the normal browser."
            )

            return False

    # --------------------------------------------------------
    # Check result
    # --------------------------------------------------------

    if isinstance(result, dict):

        if result.get(
            "success",
            False,
        ):

            st.success(
                "🛡️ Website successfully opened "
                "inside Kali Linux Chrome."
            )

            if result.get(
                "vmware_focused",
                False,
            ):

                st.info(
                    "🖥️ VMware Workstation was brought to the foreground."
                )

            return True

        else:

            st.error(
                "❌ Failed to open website inside Kali Linux Chrome."
            )

            st.code(
                result.get(
                    "message",
                    "Unknown VM Chrome error.",
                )
            )

            st.error(
                "🔒 Website remains blocked. "
                "It will NOT be opened in the normal browser."
            )

            return False

    else:

        if result:

            st.success(
                "🛡️ Website opened inside Kali Linux Chrome."
            )

            return True

        st.error(
            "❌ Failed to open website inside Kali Linux Chrome."
        )

        st.error(
            "🔒 Website remains blocked. "
            "It will NOT be opened in the normal browser."
        )

        return False


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header(
        "⚙️ System Status"
    )

    st.success(
        "🤖 Ensemble ML Ready"
    )

    st.write(
        "**Models:**"
    )

    st.write(
        "• Logistic Regression"
    )

    st.write(
        "• Random Forest"
    )

    st.write(
        "• XGBoost"
    )

    st.write(
        "• LightGBM"
    )

    st.write(
        f"**Features:** {len(FEATURE_NAMES)}"
    )

    st.divider()

    st.write(
        "**Browser Security Policy**"
    )

    st.write(
        "🟢 0–24 → Normal Browser"
    )

    st.write(
        "🟡 25–49 → VM Chrome"
    )

    st.write(
        "🟠 50–74 → VM Chrome"
    )

    st.write(
        "🔴 75–100 → VM Chrome"
    )

    st.divider()

    if LOCAL_WINDOWS_MODE:

        if vm_available():

            st.success(
                "🖥️ Kali VM Connected"
            )

        else:

            st.error(
                "❌ Kali VM Not Connected"
            )

        if chrome_available():

            st.success(
                "🌐 Chrome Available"
            )

        else:

            st.error(
                "❌ Chrome Not Available"
            )

    else:

        st.warning(
            "Cloud mode: local VM unavailable."
        )


# ============================================================
# URL INPUT
# ============================================================

st.subheader(
    "🔍 Analyze Website"
)

url = st.text_input(
    "Enter website URL",
    placeholder="https://example.com",
    key="url_input",
)

analyze = st.button(
    "🔎 Scan Website",
    type="primary",
    width="stretch",
)


# ============================================================
# SCAN
# ============================================================

if analyze:

    normalized_url = prepare_url(url)

    if not normalized_url:

        st.warning(
            "Please enter a valid URL."
        )

        st.stop()

    # --------------------------------------------------------
    # STATIC
    # --------------------------------------------------------

    with st.spinner(
        "1/4 Analyzing URL and domain..."
    ):

        try:

            features = get_features(
                normalized_url
            )

            vector = get_feature_vector(
                features
            )

            if len(vector) != len(
                FEATURE_NAMES
            ):

                raise ValueError(
                    f"Expected {len(FEATURE_NAMES)} "
                    f"features but received {len(vector)}."
                )

            probability = predict_ml(
                vector
            )

            ml_score = (
                probability * 100
            )

            url_score, url_reasons = (
                rule_score(
                    features
                )
            )

        except Exception as exc:

            st.error(
                f"Static analysis failed: {exc}"
            )

            st.exception(exc)

            st.stop()

    # --------------------------------------------------------
    # DYNAMIC WEBSITE ANALYSIS
    # --------------------------------------------------------

    with st.spinner(
        "2/4 Scanning website content and Kali headless Chrome..."
    ):

        try:

            dynamic = analyze_dynamic_url(
                normalized_url
            )

        except Exception as exc:

            dynamic = {
                "success": False,
                "inside_scan": False,
                "error": str(exc),
            }

    # --------------------------------------------------------
    # CONTENT
    # --------------------------------------------------------

    with st.spinner(
        "3/4 Analyzing rendered website content..."
    ):

        content_score, content_reasons = (
            content_risk(
                dynamic
            )
        )

    # --------------------------------------------------------
    # FINAL
    # --------------------------------------------------------

    with st.spinner(
        "4/4 Calculating final risk..."
    ):

        final_score = calculate_final_risk(
            ml_score,
            url_score,
            content_score,
        )

        level, icon = risk_level(
            final_score
        )

        browser_decision = get_browser_decision(
            final_score
        )

    # --------------------------------------------------------
    # SAVE COMPLETE RESULT
    # --------------------------------------------------------

    st.session_state["scan_result"] = {

        "url": normalized_url,

        "features": features,

        "dynamic": dynamic,

        "ml_score": ml_score,

        "url_score": url_score,

        "content_score": content_score,

        "final_score": final_score,

        "level": level,

        "icon": icon,

        "browser_decision": browser_decision,

        "url_reasons": url_reasons,

        "content_reasons": content_reasons,
    }


# ============================================================
# DISPLAY SAVED RESULT
# ============================================================

if "scan_result" in st.session_state:

    result = st.session_state[
        "scan_result"
    ]

    normalized_url = result[
        "url"
    ]

    features = result[
        "features"
    ]

    dynamic = result[
        "dynamic"
    ]

    ml_score = result[
        "ml_score"
    ]

    url_score = result[
        "url_score"
    ]

    content_score = result[
        "content_score"
    ]

    final_score = result[
        "final_score"
    ]

    level = result[
        "level"
    ]

    icon = result[
        "icon"
    ]

    browser_decision = result[
        "browser_decision"
    ]

    url_reasons = result[
        "url_reasons"
    ]

    content_reasons = result[
        "content_reasons"
    ]

    # ========================================================
    # RESULT
    # ========================================================

    st.divider()

    st.subheader(
        "📊 Final Website Risk"
    )

    col1, col2, col3 = st.columns(
        3
    )

    with col1:

        st.metric(
            "Risk Score",
            f"{final_score:.1f}/100",
        )

    with col2:

        st.metric(
            "Risk Level",
            f"{icon} {level}",
        )

    with col3:

        st.metric(
            "ML Probability",
            f"{ml_score:.1f}%",
        )

    st.progress(
        int(
            min(
                100,
                max(
                    0,
                    round(
                        final_score
                    ),
                ),
            )
        )
    )

    # ========================================================
    # SECURITY DECISION
    # ========================================================

    st.subheader(
        "🛡️ Security Decision"
    )

    if final_score < 25:

        st.success(
            "🟢 SAFE — Normal Windows browser is allowed."
        )

        st.info(
            "Security decision: NORMAL WINDOWS BROWSER"
        )

    elif final_score < 50:

        st.warning(
            "🟡 SUSPICIOUS — Website will ONLY open "
            "inside Kali Linux VM Chrome."
        )

        st.info(
            "🔒 Security decision: VM CHROME"
        )

    elif final_score < 75:

        st.warning(
            "🟠 HIGH RISK — Website will ONLY open "
            "inside Kali Linux VM Chrome."
        )

        st.info(
            "🔒 Security decision: VM CHROME"
        )

    else:

        st.error(
            "🔴 CRITICAL — Website will ONLY open "
            "inside Kali Linux VM Chrome."
        )

        st.info(
            "🔒 Security decision: VM CHROME"
        )

    st.write(
        f"**Scanned URL:** `{normalized_url}`"
    )

    # ========================================================
    # OPEN WEBSITE
    # ========================================================

    st.subheader(
        "🌐 Website Opening"
    )

    # --------------------------------------------------------
    # SAFE
    # --------------------------------------------------------

    if final_score < 25:

        if st.button(
            "🌐 Open in Normal Browser",
            key="open_safe_normal_browser",
            type="primary",
            width="stretch",
        ):

            open_in_normal_browser(
                normalized_url
            )

    # --------------------------------------------------------
    # SUSPICIOUS / HIGH / CRITICAL
    # --------------------------------------------------------

    else:

        if level == "SUSPICIOUS":

            st.warning(
                "🟡 SUSPICIOUS WEBSITE — "
                "Normal Windows Chrome is blocked."
            )

        elif level == "HIGH RISK":

            st.warning(
                "🟠 HIGH RISK WEBSITE — "
                "Normal Windows Chrome is blocked."
            )

        else:

            st.error(
                "🔴 CRITICAL WEBSITE — "
                "Normal Windows Chrome is blocked."
            )

        if st.button(
            "🛡️ Open in VM Linux Chrome",
            key="open_risky_vm",
            type="primary",
            width="stretch",
        ):

            open_in_kali_vm(
                normalized_url
            )

    # ========================================================
    # ISOLATION DECISION
    # ========================================================

    st.subheader(
        "🔐 Browser Isolation"
    )

    if final_score >= 25:

        st.error(
            "🔒 ISOLATED — Kali Linux VM Chrome"
        )

        st.caption(
            "Suspicious, High Risk, and Critical websites "
            "cannot be opened in the normal Windows browser."
        )

    else:

        st.success(
            "🟢 NOT REQUIRED — Normal Windows Browser"
        )

    # ========================================================
    # SCORE BREAKDOWN
    # ========================================================

    st.subheader(
        "📈 Risk Score Breakdown"
    )

    b1, b2, b3 = st.columns(
        3
    )

    with b1:

        st.metric(
            "ML Score",
            f"{ml_score:.1f}",
        )

        st.caption(
            "55% weight"
        )

    with b2:

        st.metric(
            "URL Rule Score",
            f"{url_score:.1f}",
        )

        st.caption(
            "20% weight"
        )

    with b3:

        st.metric(
            "Content Score",
            f"{content_score:.1f}",
        )

        st.caption(
            "25% weight"
        )

    # ========================================================
    # REASONS
    # ========================================================

    st.subheader(
        "🔎 Why this score?"
    )

    all_reasons = (
        url_reasons
        + content_reasons
    )

    if all_reasons:

        for reason in dict.fromkeys(
            all_reasons
        ):

            st.write(
                f"• {reason}"
            )

    else:

        st.success(
            "No major suspicious indicators were detected."
        )

    # ========================================================
    # SCAN STATUS
    # ========================================================

    st.subheader(
        "🧪 Scan Results"
    )

    http_success = dynamic.get(
        "success",
        False,
    )

    inside_success = dynamic.get(
        "inside_scan",
        False,
    )

    c1, c2 = st.columns(
        2
    )

    with c1:

        if http_success:

            st.success(
                "✅ External HTTP/HTML scan completed"
            )

        else:

            st.warning(
                "⚠️ External HTTP scan could not be completed"
            )

    with c2:

        if inside_success:

            st.success(
                "✅ Kali headless Chrome scan completed"
            )

        else:

            st.warning(
                "⚠️ Kali rendered scan unavailable"
            )

    # ========================================================
    # DYNAMIC CONTENT
    # ========================================================

    st.subheader(
        "🌐 Website Content Findings"
    )

    rendered = dynamic.get(
        "rendered",
        {},
    )

    if rendered:

        a, b, c, d = st.columns(
            4
        )

        with a:

            st.metric(
                "Forms",
                rendered.get(
                    "form_count",
                    0,
                ),
            )

        with b:

            st.metric(
                "Password Forms",
                rendered.get(
                    "password_forms",
                    0,
                ),
            )

        with c:

            st.metric(
                "JavaScript",
                rendered.get(
                    "javascript_count",
                    0,
                ),
            )

        with d:

            st.metric(
                "Suspicious JS",
                rendered.get(
                    "suspicious_javascript",
                    0,
                ),
            )

        st.write(
            "**Page title:**",
            rendered.get(
                "title",
                "",
            ),
        )

        st.write(
            "**Suspicious content indicators:**",
            rendered.get(
                "suspicious_keywords",
                0,
            ),
        )

        st.write(
            "**Cross-domain forms:**",
            rendered.get(
                "cross_domain_forms",
                0,
            ),
        )

        st.write(
            "**Iframes:**",
            rendered.get(
                "iframe_count",
                0,
            ),
        )

    # ========================================================
    # REDIRECTS / DOWNLOADS
    # ========================================================

    st.write(
        "**Redirects:**",
        dynamic.get(
            "redirect_count",
            0,
        ),
    )

    st.write(
        "**Downloads detected:**",
        dynamic.get(
            "download_count",
            0,
        ),
    )

    # ========================================================
    # URL FEATURES
    # ========================================================

    with st.expander(
        "🔬 View 41 URL features"
    ):

        for index, name in enumerate(
            FEATURE_NAMES,
            1,
        ):

            st.write(
                f"{index}. **{name}** = "
                f"`{features.get(name, 0)}`"
            )

    # ========================================================
    # MODEL INFORMATION
    # ========================================================

    with st.expander(
        "🤖 Model information"
    ):

        st.write(
            "Logistic Regression + "
            "Random Forest + XGBoost + "
            "LightGBM"
        )

        st.write(
            "Soft-voting ensemble"
        )

        st.write(
            "Weights: LR=1, RF=2, XGB=2, LGBM=2"
        )

        st.write(
            f"Features: {len(FEATURE_NAMES)}"
        )

    # ========================================================
    # VM INFORMATION
    # ========================================================

    with st.expander(
        "🖥️ Kali VM information"
    ):

        st.json(
            get_vm_info()
        )