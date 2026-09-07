from pathlib import Path
import sys
import webbrowser
import joblib
import streamlit as st
import os


# ============================================================
# PROJECT ROOT
# ============================================================

PROJECT_ROOT = Path(__file__).resolve().parent

if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))


# ============================================================
# DEPLOYMENT ENVIRONMENT
# ============================================================

# VMware/Kali integration works only when this application
# is running locally on the Windows computer hosting VMware.

LOCAL_WINDOWS_MODE = os.name == "nt"

if LOCAL_WINDOWS_MODE:
    DEPLOYMENT_MODE = "LOCAL WINDOWS"
else:
    DEPLOYMENT_MODE = "STREAMLIT CLOUD / SERVER"


# ============================================================
# PROJECT IMPORTS
# ============================================================

from app.features.url_features import (
    get_features,
    get_feature_vector,
    FEATURE_NAMES,
    normalize_url,
)


# ============================================================
# OPTIONAL FEATURE HELPERS
# ============================================================

try:

    from app.features.url_features import (
        analyze_url_input,
        is_known_legitimate_domain,
        get_registered_domain,
    )

except ImportError:

    def analyze_url_input(value):

        normalized = normalize_url(value)

        return {
            "original": value,
            "normalized": normalized,
            "valid": bool(normalized),
        }


    def is_known_legitimate_domain(domain):

        return False


    def get_registered_domain(domain):

        return domain


# ============================================================
# KALI VM IMPORTS
# ============================================================

# IMPORTANT:
# The Kali VM is a LOCAL VMware guest.
#
# When running locally on Windows:
#     Streamlit -> Windows -> VMware -> Kali -> Chrome
#
# When running on Streamlit Cloud:
#     Streamlit Cloud -> X
#
# Streamlit Cloud cannot directly access your local
# Kali VM at 192.168.29.129.

if LOCAL_WINDOWS_MODE:

    try:

        from app.vm_launcher import (
            vm_available,
            chrome_available,
            get_vm_info,
            get_vm_connection_status,
            open_url_in_vm,
            start_kali_vm,
        )

        VM_LAUNCHER_AVAILABLE = True
        VM_IMPORT_ERROR = None

    except Exception as e:

        VM_LAUNCHER_AVAILABLE = False
        VM_IMPORT_ERROR = str(e)

        def vm_available():
            return False

        def chrome_available():
            return False

        def get_vm_info():

            return {
                "available": False,
                "environment": DEPLOYMENT_MODE,
                "message": VM_IMPORT_ERROR,
            }

        def get_vm_connection_status():

            return {
                "connected": False,
                "message": VM_IMPORT_ERROR,
            }

        def open_url_in_vm(url):

            return {
                "success": False,
                "url": url,
                "message": (
                    "VM launcher could not be imported: "
                    + VM_IMPORT_ERROR
                ),
            }

        def start_kali_vm():

            return {
                "success": False,
                "started": False,
                "message": (
                    "VM launcher could not be imported: "
                    + VM_IMPORT_ERROR
                ),
            }


else:

    # ========================================================
    # STREAMLIT CLOUD / SERVER FALLBACK
    # ========================================================

    VM_LAUNCHER_AVAILABLE = False

    VM_IMPORT_ERROR = (
        "Local Kali Linux VMware integration is unavailable "
        "when the application is running on Streamlit Cloud."
    )


    def vm_available():

        return False


    def chrome_available():

        return False


    def get_vm_info():

        return {

            "available": False,

            "environment":
                DEPLOYMENT_MODE,

            "message":
                (
                    "The Kali Linux VM is running on the "
                    "local Windows computer, not on "
                    "Streamlit Cloud."
                ),

            "vm_host":
                "192.168.29.129",

        }


    def get_vm_connection_status():

        return {

            "connected": False,

            "message":
                (
                    "Streamlit Cloud cannot directly access "
                    "the Kali Linux VM running on the local "
                    "Windows/VMware computer."
                ),

            "environment":
                DEPLOYMENT_MODE,

        }


    def open_url_in_vm(url):

        return {

            "success": False,

            "url": url,

            "message":
                (
                    "Kali Linux VM isolation is available "
                    "only when Streamlit is running locally "
                    "on the Windows computer hosting VMware."
                ),

            "environment":
                DEPLOYMENT_MODE,

        }


    def start_kali_vm():

        return {

            "success": False,

            "started": False,

            "message":
                (
                    "Cannot start the local VMware Kali VM "
                    "from Streamlit Cloud."
                ),

            "environment":
                DEPLOYMENT_MODE,

        }


# ============================================================
# OPTIONAL DYNAMIC ANALYZER
# ============================================================

try:

    from app.analyzers.dynamic_analyzer import (
        analyze_dynamic_url
    )

    DYNAMIC_AVAILABLE = True

except Exception:

    analyze_dynamic_url = None
    DYNAMIC_AVAILABLE = False


# ============================================================
# PAGE CONFIG
# ============================================================

st.set_page_config(
    page_title="AI Browser Security",
    page_icon="🛡️",
    layout="wide",
)


# ============================================================
# CSS
# ============================================================

st.markdown(
    """
    <style>

    .risk-card {
        padding: 20px;
        border-radius: 15px;
        border: 1px solid #ddd;
        margin-bottom: 15px;
    }

    .safe-card {
        padding: 20px;
        border-radius: 15px;
        background: #e8f5e9;
        border: 2px solid #4caf50;
    }

    .danger-card {
        padding: 20px;
        border-radius: 15px;
        background: #ffebee;
        border: 2px solid #f44336;
    }

    .warning-card {
        padding: 20px;
        border-radius: 15px;
        background: #fff8e1;
        border: 2px solid #ff9800;
    }

    .vm-card {
        padding: 20px;
        border-radius: 15px;
        background: #e3f2fd;
        border: 2px solid #2196f3;
    }

    .info-card {
        padding: 20px;
        border-radius: 15px;
        background: #f5f5f5;
        border: 1px solid #bbb;
    }

    </style>
    """,
    unsafe_allow_html=True,
)


# ============================================================
# TITLE
# ============================================================

st.title("🛡️ AI Browser Security")

st.caption(
    "Adaptive Risk-Based Browser Isolation Using Multi-Signal AI"
)


# ============================================================
# MODEL PATHS
# ============================================================

MODEL_PATHS = [

    PROJECT_ROOT
    / "models"
    / "url_risk_model.joblib",

    PROJECT_ROOT
    / "app"
    / "ml"
    / "url_risk_model.joblib",

]


# ============================================================
# MODEL LOADING
# ============================================================

@st.cache_resource
def load_model():

    for path in MODEL_PATHS:

        if path.exists():

            try:

                model = joblib.load(path)

                return model, path, None

            except Exception as e:

                return (
                    None,
                    path,
                    str(e),
                )

    return (
        None,
        None,
        "Model file not found.",
    )


model, model_path, model_error = load_model()


# ============================================================
# MODEL VALIDATION
# ============================================================

if model is None:

    st.error(
        "❌ ML model could not be loaded."
    )

    st.error(
        model_error
        or "Unknown model loading error."
    )

    st.info(
        "Expected model location:"
    )

    st.code(
        str(
            PROJECT_ROOT
            / "models"
            / "url_risk_model.joblib"
        )
    )

    st.stop()


MODEL_FEATURE_COUNT = getattr(
    model,
    "n_features_in_",
    None,
)


APP_FEATURE_COUNT = len(
    FEATURE_NAMES
)


if (
    MODEL_FEATURE_COUNT is not None
    and
    MODEL_FEATURE_COUNT
    != APP_FEATURE_COUNT
):

    st.error(
        "❌ MODEL FEATURE MISMATCH"
    )

    st.write(
        f"Model expects: "
        f"**{MODEL_FEATURE_COUNT} features**"
    )

    st.write(
        f"Application provides: "
        f"**{APP_FEATURE_COUNT} features**"
    )

    st.warning(
        "The RandomForest model and feature "
        "extractor are not compatible."
    )

    st.code(
        """
python -c "import joblib; m=joblib.load('models/url_risk_model.joblib'); print('Features:',m.n_features_in_); print('Classes:',m.classes_)"
        """
    )

    st.stop()


# ============================================================
# SESSION STATE
# ============================================================

if "analysis" not in st.session_state:
    st.session_state.analysis = None

if "dynamic" not in st.session_state:
    st.session_state.dynamic = None

if "analyzed_url" not in st.session_state:
    st.session_state.analyzed_url = ""

if "input_url" not in st.session_state:
    st.session_state.input_url = ""


# ============================================================
# HELPER
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


# ============================================================
# URL PREPARATION
# ============================================================

def prepare_url(user_input):

    if user_input is None:
        return None

    value = str(
        user_input
    ).strip()

    if not value:
        return None

    try:

        normalized = normalize_url(
            value
        )

    except Exception:

        normalized = value

        if not normalized.lower().startswith(
            (
                "http://",
                "https://",
            )
        ):

            normalized = (
                "https://"
                + normalized
            )

    normalized = normalized.strip()

    if not normalized.lower().startswith(
        (
            "http://",
            "https://",
        )
    ):

        normalized = (
            "https://"
            + normalized
        )

    return normalized


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(user_input):

    normalized = prepare_url(
        user_input
    )

    if not normalized:

        return (
            False,
            None,
            "URL is empty.",
        )

    try:

        parsed_info = analyze_url_input(
            normalized
        )

        if isinstance(
            parsed_info,
            dict,
        ):

            valid = parsed_info.get(
                "valid",
                True,
            )

            if not valid:

                return (
                    False,
                    normalized,
                    "The entered value is not "
                    "a valid website URL.",
                )

    except Exception:

        pass

    from urllib.parse import urlparse

    parsed = urlparse(
        normalized
    )

    if parsed.scheme.lower() not in (
        "http",
        "https",
    ):

        return (
            False,
            normalized,
            "Only HTTP and HTTPS URLs "
            "are supported.",
        )

    if not parsed.netloc:

        return (
            False,
            normalized,
            "No valid domain or IP "
            "address was detected.",
        )

    return (
        True,
        normalized,
        None,
    )


# ============================================================
# ML MALICIOUS PROBABILITY
# ============================================================

def get_malicious_probability(
    feature_dict
):

    try:

        vector = get_feature_vector(
            feature_dict
        )

        if (
            MODEL_FEATURE_COUNT is not None
            and
            len(vector)
            != MODEL_FEATURE_COUNT
        ):

            raise ValueError(
                f"Feature vector contains "
                f"{len(vector)} features but "
                f"model expects "
                f"{MODEL_FEATURE_COUNT}."
            )

        probability = (
            model.predict_proba(
                [vector]
            )[0]
        )

        classes = getattr(
            model,
            "classes_",
            [0, 1],
        )

        malicious_index = None

        for index, cls in enumerate(
            classes
        ):

            try:

                if int(cls) == 1:

                    malicious_index = index

                    break

            except Exception:

                continue

        if malicious_index is None:

            malicious_index = (
                len(probability) - 1
            )

        return float(
            probability[
                malicious_index
            ]
        )

    except Exception as e:

        st.error(
            f"ML prediction error: {e}"
        )

        return 0.0


# ============================================================
# RULE-BASED RISK ENGINE
# ============================================================

def calculate_rule_score(
    features
):

    score = 0

    reasons = []


    if features.get(
        "has_ip",
        0,
    ):

        score += 25

        reasons.append(
            "Website uses an IP address "
            "instead of a normal domain."
        )


    if features.get(
        "has_at_symbol",
        0,
    ):

        score += 30

        reasons.append(
            "URL contains '@', which can "
            "disguise the actual destination."
        )


    if features.get(
        "punycode",
        0,
    ):

        score += 30

        reasons.append(
            "Punycode detected; this can "
            "be used for domain impersonation."
        )


    if features.get(
        "homograph",
        0,
    ):

        score += 35

        reasons.append(
            "Possible homograph attack detected."
        )


    if features.get(
        "brand_impersonation",
        0,
    ):

        score += 30

        reasons.append(
            "Possible brand impersonation detected."
        )


    if features.get(
        "typosquatting",
        0,
    ):

        score += 25

        reasons.append(
            "Possible typosquatting domain detected."
        )


    if features.get(
        "suspicious_keywords",
        0,
    ):

        score += 15

        reasons.append(
            "URL contains suspicious "
            "security/login/payment keywords."
        )


    if features.get(
        "suspicious_tld",
        0,
    ):

        score += 12

        reasons.append(
            "Suspicious or commonly abused "
            "TLD detected."
        )


    if features.get(
        "url_shortener",
        0,
    ):

        score += 10

        reasons.append(
            "URL shortening service detected."
        )


    if features.get(
        "unusual_port",
        0,
    ):

        score += 12

        reasons.append(
            "Unusual network port detected."
        )


    if features.get(
        "is_http",
        0,
    ):

        score += 10

        reasons.append(
            "Website is using HTTP instead "
            "of HTTPS."
        )


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
            "URL contains an unusually large "
            "number of subdomains."
        )


    if features.get(
        "num_parameters",
        0,
    ) >= 6:

        score += 8

        reasons.append(
            "URL contains many parameters."
        )


    if features.get(
        "domain_entropy",
        0,
    ) >= 4:

        score += 8

        reasons.append(
            "Domain has high character "
            "randomness/entropy."
        )


    if features.get(
        "dns_private_ip",
        0,
    ):

        score += 20

        reasons.append(
            "Domain resolves to a private "
            "IP address."
        )


    return (
        clamp(score),
        reasons,
    )


# ============================================================
# STRONG MALICIOUS INDICATORS
# ============================================================

def has_strong_malicious_indicators(
    features
):

    indicators = [

        features.get(
            "homograph",
            0,
        ),

        features.get(
            "brand_impersonation",
            0,
        ),

        features.get(
            "typosquatting",
            0,
        ),

        features.get(
            "punycode",
            0,
        ),

        features.get(
            "has_at_symbol",
            0,
        ),

        features.get(
            "dns_private_ip",
            0,
        ),

    ]

    return any(
        bool(x)
        for x in indicators
    )


# ============================================================
# LEGITIMATE DOMAIN ADJUSTMENT
# ============================================================

def apply_legitimate_domain_adjustment(
    features,
    final_score,
    reasons,
    normalized_url,
):

    try:

        from urllib.parse import urlparse

        parsed = urlparse(
            normalized_url
        )

        hostname = (
            parsed.hostname
            or ""
        ).lower().strip()

        if not hostname:

            return (
                final_score,
                False,
            )

        legitimate = False

        try:

            legitimate = (
                is_known_legitimate_domain(
                    hostname
                )
            )

        except Exception:

            legitimate = False

        if not legitimate:

            return (
                final_score,
                False,
            )

        if has_strong_malicious_indicators(
            features
        ):

            return (
                final_score,
                False,
            )

        adjusted_score = min(
            final_score,
            10.0,
        )

        if (
            adjusted_score
            != final_score
        ):

            reasons.insert(
                0,
                (
                    f"Recognized legitimate domain: "
                    f"{hostname}. No strong malicious "
                    f"indicators were detected."
                ),
            )

        return (
            adjusted_score,
            True,
        )

    except Exception:

        return (
            final_score,
            False,
        )


# ============================================================
# FORCE ISOLATION
# ============================================================

def mandatory_isolation(
    features,
    rule_score,
):

    if features.get(
        "homograph",
        0,
    ):

        return (
            True,
            "Homograph attack detected.",
        )


    if features.get(
        "brand_impersonation",
        0,
    ):

        return (
            True,
            "Possible brand impersonation detected.",
        )


    if features.get(
        "punycode",
        0,
    ):

        return (
            True,
            "Punycode-based suspicious domain detected.",
        )


    if features.get(
        "typosquatting",
        0,
    ):

        return (
            True,
            "Possible typosquatting detected.",
        )


    if features.get(
        "has_at_symbol",
        0,
    ):

        return (
            True,
            "Deceptive '@' URL structure detected.",
        )


    strong_indicators = 0


    strong_indicators += int(
        bool(
            features.get(
                "has_ip",
                0,
            )
        )
    )


    strong_indicators += int(
        bool(
            features.get(
                "suspicious_keywords",
                0,
            )
        )
    )


    strong_indicators += int(
        bool(
            features.get(
                "suspicious_tld",
                0,
            )
        )
    )


    strong_indicators += int(
        bool(
            features.get(
                "unusual_port",
                0,
            )
        )
    )


    strong_indicators += int(
        bool(
            features.get(
                "url_shortener",
                0,
            )
        )
    )


    if strong_indicators >= 2:

        return (
            True,
            "Multiple suspicious URL indicators detected.",
        )


    if rule_score >= 40:

        return (
            True,
            (
                f"Rule-based risk score is "
                f"{rule_score:.0f}/100."
            ),
        )


    return (
        False,
        "",
    )


# ============================================================
# STATIC RISK
# ============================================================

def calculate_static_risk(
    features,
    normalized_url,
):

    ml_probability = (
        get_malicious_probability(
            features
        )
    )

    ml_score = (
        ml_probability * 100
    )


    rule_score, reasons = (
        calculate_rule_score(
            features
        )
    )


    final_score = (
        ml_score * 0.60
        +
        rule_score * 0.40
    )

    final_score = clamp(
        final_score
    )


    (
        final_score,
        recognized_legitimate,
    ) = apply_legitimate_domain_adjustment(
        features,
        final_score,
        reasons,
        normalized_url,
    )


    (
        force_vm,
        force_reason,
    ) = mandatory_isolation(
        features,
        rule_score,
    )


    if force_vm:

        final_score = max(
            final_score,
            50,
        )

        if force_reason not in reasons:

            reasons.insert(
                0,
                force_reason,
            )


    if final_score >= 75:

        risk_level = "CRITICAL"
        isolation = "KALI VM"

    elif final_score >= 50:

        risk_level = "HIGH"
        isolation = "KALI VM"

    elif final_score >= 25:

        risk_level = "MEDIUM"
        isolation = "KALI VM"

    else:

        risk_level = "LOW"
        isolation = "NORMAL BROWSER"


    return {

        "ml_score":
            ml_score,

        "rule_score":
            rule_score,

        "final_score":
            final_score,

        "risk_level":
            risk_level,

        "isolation":
            isolation,

        "reasons":
            reasons,

        "force_vm":
            force_vm,

        "recognized_legitimate":
            recognized_legitimate,

    }


# ============================================================
# DYNAMIC RISK
# ============================================================

def calculate_dynamic_risk(
    static_result,
    dynamic,
):

    if not dynamic:

        return static_result


    final_score = (
        static_result[
            "final_score"
        ]
    )


    reasons = list(
        static_result[
            "reasons"
        ]
    )


    if dynamic.get(
        "downloads",
        0,
    ):

        final_score += 30

        reasons.append(
            "Page attempted a file download."
        )


    if dynamic.get(
        "suspicious_js",
        0,
    ):

        final_score += 25

        reasons.append(
            "Suspicious JavaScript behavior detected."
        )


    if dynamic.get(
        "password_form",
        0,
    ):

        final_score += 25

        reasons.append(
            "Password/login form detected."
        )


    redirects = dynamic.get(
        "redirect_count",
        0,
    )

    if redirects >= 3:

        final_score += 20

        reasons.append(
            f"Multiple redirects detected ({redirects})."
        )


    final_score = clamp(
        final_score
    )


    if dynamic.get(
        "downloads",
        0,
    ):

        final_score = max(
            final_score,
            60,
        )


    if dynamic.get(
        "password_form",
        0,
    ):

        final_score = max(
            final_score,
            55,
        )


    if dynamic.get(
        "suspicious_js",
        0,
    ):

        final_score = max(
            final_score,
            60,
        )


    if final_score >= 75:

        risk_level = "CRITICAL"
        isolation = "KALI VM"

    elif final_score >= 50:

        risk_level = "HIGH"
        isolation = "KALI VM"

    elif final_score >= 25:

        risk_level = "MEDIUM"
        isolation = "KALI VM"

    else:

        risk_level = "LOW"
        isolation = "NORMAL BROWSER"


    return {

        "ml_score":
            static_result[
                "ml_score"
            ],

        "rule_score":
            static_result[
                "rule_score"
            ],

        "final_score":
            final_score,

        "risk_level":
            risk_level,

        "isolation":
            isolation,

        "reasons":
            reasons,

        "force_vm":
            static_result[
                "force_vm"
            ],

        "recognized_legitimate":
            static_result.get(
                "recognized_legitimate",
                False,
            ),

    }


# ============================================================
# SIDEBAR
# ============================================================

with st.sidebar:

    st.header(
        "⚙️ System Status"
    )


    st.success(
        "🤖 AI Model Loaded"
    )


    st.write(
        f"**Model:** `{model_path.name}`"
    )


    st.write(
        f"**Features:** `{MODEL_FEATURE_COUNT}`"
    )


    st.divider()


    # ========================================================
    # DEPLOYMENT STATUS
    # ========================================================

    st.subheader(
        "🚀 Deployment"
    )


    if LOCAL_WINDOWS_MODE:

        st.success(
            "🪟 Local Windows Mode"
        )

        st.caption(
            "This application is running on the "
            "Windows computer that hosts VMware."
        )

    else:

        st.info(
            "☁️ Streamlit Cloud Mode"
        )

        st.caption(
            "This application is running on a "
            "remote Streamlit server."
        )


    st.divider()


    # ========================================================
    # KALI VM STATUS
    # ========================================================

    if LOCAL_WINDOWS_MODE:

        vm_ok = False
        chrome_ok = False


        try:

            vm_ok = vm_available()

        except Exception:

            vm_ok = False


        if vm_ok:

            try:

                chrome_ok = chrome_available()

            except Exception:

                chrome_ok = False


        if vm_ok:

            st.success(
                "🖥️ Kali VM Connected"
            )

        else:

            st.error(
                "❌ Kali VM Not Connected"
            )


        if chrome_ok:

            st.success(
                "🌐 Chrome Available"
            )

        else:

            st.error(
                "❌ Chrome Not Available"
            )


    else:

        st.warning(
            "☁️ Local Kali VM unavailable"
        )

        st.info(
            "Your Kali VM runs on your local "
            "Windows computer. Streamlit Cloud "
            "cannot directly access it."
        )


    st.divider()


    # ========================================================
    # ISOLATION POLICY
    # ========================================================

    st.subheader(
        "Isolation Policy"
    )


    st.write(
        "**Risk < 25** → Windows Browser"
    )


    st.write(
        "**Risk ≥ 25** → Kali VM Chrome"
    )


    st.divider()


    if LOCAL_WINDOWS_MODE:

        st.caption(
            "Suspicious websites are opened inside "
            "the isolated Kali Linux VM instead of "
            "the normal Windows browser."
        )

    else:

        st.caption(
            "AI detection works in Streamlit Cloud. "
            "Run the application locally on Windows "
            "to use VMware/Kali browser isolation."
        )


# ============================================================
# URL INPUT
# ============================================================

st.subheader(
    "🔍 Analyze Website"
)


url = st.text_input(
    "Enter website URL",
    placeholder=(
        "google.com or "
        "https://example.com/login"
    ),
)


col1, col2 = st.columns(
    [3, 1]
)


with col1:

    analyze_button = st.button(
        "🔎 Analyze URL",
        type="primary",
        use_container_width=True,
    )


with col2:

    clear_button = st.button(
        "🗑️ Clear",
        use_container_width=True,
    )


# ============================================================
# CLEAR
# ============================================================

if clear_button:

    st.session_state.analysis = None
    st.session_state.dynamic = None
    st.session_state.analyzed_url = ""
    st.session_state.input_url = ""

    st.rerun()


# ============================================================
# ANALYZE
# ============================================================

if analyze_button:

    if not url.strip():

        st.warning(
            "Please enter a website URL."
        )

    else:

        valid, normalized_url, error = (
            validate_url(url)
        )

        if not valid:

            st.error(
                f"❌ {error}"
            )

        else:

            st.session_state.dynamic = None

            with st.spinner(
                "Analyzing URL with "
                "41-feature AI model..."
            ):

                try:

                    # STEP 1
                    feature_dict = (
                        get_features(
                            normalized_url
                        )
                    )


                    # STEP 2
                    feature_vector = (
                        get_feature_vector(
                            feature_dict
                        )
                    )


                    # STEP 3
                    if len(
                        feature_vector
                    ) != 41:

                        raise ValueError(
                            "Feature extractor returned "
                            f"{len(feature_vector)} features. "
                            "Expected exactly 41."
                        )


                    # STEP 4
                    static_result = (
                        calculate_static_risk(
                            feature_dict,
                            normalized_url,
                        )
                    )


                    # SAVE RESULT
                    st.session_state.analysis = {

                        "original_url":
                            url.strip(),

                        "url":
                            normalized_url,

                        "features":
                            feature_dict,

                        "vector":
                            feature_vector,

                        "result":
                            static_result,

                    }


                    st.session_state.analyzed_url = (
                        normalized_url
                    )


                except Exception as e:

                    st.error(
                        f"❌ Analysis failed: {e}"
                    )

                    st.stop()


# ============================================================
# DISPLAY ANALYSIS
# ============================================================

if st.session_state.analysis:

    analysis = (
        st.session_state.analysis
    )


    analyzed_url = (
        analysis["url"]
    )


    original_url = (
        analysis.get(
            "original_url",
            analyzed_url,
        )
    )


    features = (
        analysis["features"]
    )


    static_result = (
        analysis["result"]
    )


    # ========================================================
    # DYNAMIC RESULT
    # ========================================================

    if (
        st.session_state.dynamic
        is not None
        and
        st.session_state.analyzed_url
        ==
        analyzed_url
    ):

        final_result = (
            calculate_dynamic_risk(
                static_result,
                st.session_state.dynamic,
            )
        )

    else:

        final_result = (
            static_result
        )


    # ========================================================
    # RESULT HEADER
    # ========================================================

    st.divider()

    st.subheader(
        "📊 Risk Assessment"
    )


    if (
        original_url
        !=
        analyzed_url
    ):

        st.write(
            f"**Entered:** "
            f"`{original_url}`"
        )

        st.write(
            f"**Normalized:** "
            f"`{analyzed_url}`"
        )

    else:

        st.write(
            f"**URL:** "
            f"`{analyzed_url}`"
        )


    # ========================================================
    # SCORE VARIABLES
    # ========================================================

    score = float(
        final_result[
            "final_score"
        ]
    )


    risk_level = (
        final_result[
            "risk_level"
        ]
    )


    isolation = (
        final_result[
            "isolation"
        ]
    )


    # ========================================================
    # METRICS
    # ========================================================

    c1, c2, c3, c4 = st.columns(
        4
    )


    with c1:

        st.metric(
            "Final Risk",
            f"{score:.1f}/100",
        )


    with c2:

        st.metric(
            "ML Score",
            (
                f"{final_result['ml_score']:.1f}"
                "/100"
            ),
        )


    with c3:

        st.metric(
            "Rule Score",
            (
                f"{final_result['rule_score']:.1f}"
                "/100"
            ),
        )


    with c4:

        st.metric(
            "Decision",
            isolation,
        )


    # ========================================================
    # RISK BAR
    # ========================================================

    st.progress(
        int(
            clamp(score)
        ),
        text=(
            f"Risk Score: "
            f"{score:.1f}/100"
        ),
    )


    # ========================================================
    # LEGITIMATE DOMAIN NOTICE
    # ========================================================

    if final_result.get(
        "recognized_legitimate",
        False,
    ):

        st.info(
            "✅ This domain is recognized as a "
            "known legitimate domain and no strong "
            "malicious indicators were detected."
        )


    # ========================================================
    # RISK MESSAGE
    # ========================================================

    if score >= 75:

        st.markdown(
            f"""
            <div class="danger-card">

            <h2>🚨 CRITICAL RISK</h2>

            <p>
            Risk Score:
            <b>{score:.1f}/100</b>
            </p>

            <p>
            This website contains strong indicators
            of potentially malicious behavior.
            </p>

            <p>
            🔒
            <b>Isolation Required:
            Kali Linux VM</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True,
        )


    elif score >= 50:

        st.markdown(
            f"""
            <div class="danger-card">

            <h2>🔴 HIGH RISK</h2>

            <p>
            Risk Score:
            <b>{score:.1f}/100</b>
            </p>

            <p>
            🔒
            <b>Isolation Required:
            Kali Linux VM</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True,
        )


    elif score >= 25:

        st.markdown(
            f"""
            <div class="warning-card">

            <h2>🟠 MEDIUM RISK</h2>

            <p>
            Risk Score:
            <b>{score:.1f}/100</b>
            </p>

            <p>
            🔒
            <b>Isolation Required:
            Kali Linux VM</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True,
        )


    else:

        st.markdown(
            f"""
            <div class="safe-card">

            <h2>🟢 LOW RISK</h2>

            <p>
            Risk Score:
            <b>{score:.1f}/100</b>
            </p>

            <p>
            🌐
            <b>Normal Windows Browser Allowed</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True,
        )


    # ========================================================
    # WHY?
    # ========================================================

    st.subheader(
        "🧠 Why was this decision made?"
    )


    reasons = (
        final_result.get(
            "reasons",
            [],
        )
    )


    if reasons:

        unique_reasons = list(
            dict.fromkeys(
                reasons
            )
        )

        for reason in unique_reasons:

            st.write(
                f"🔸 {reason}"
            )

    else:

        st.write(
            "No major suspicious indicators "
            "were detected."
        )


    # ========================================================
    # ISOLATION DECISION
    # ========================================================

    st.subheader(
        "🔐 Browser Isolation Decision"
    )


    if score >= 25:

        st.markdown(
            f"""
            <div class="vm-card">

            <h3>🖥️ Kali Linux VM Isolation</h3>

            <p>
            Risk Score:
            <b>{score:.1f}/100</b>
            </p>

            <p>
            Because the risk score is
            <b>≥ 25</b>, the website will NOT be
            opened in the normal Windows browser.
            </p>

            <p>
            Target:
            <b>Google Chrome inside Kali Linux VM</b>
            </p>

            </div>
            """,
            unsafe_allow_html=True,
        )

    else:

        st.info(
            f"Risk score is {score:.1f}/100, "
            "which is below the isolation threshold "
            "of 25. Normal browser access is allowed."
        )


    # ========================================================
    # BROWSER ACCESS
    # ========================================================

    st.subheader(
        "🌐 Browser Access"
    )


    # ========================================================
    # UNSAFE WEBSITE → KALI VM
    # ========================================================

    if score >= 25:

        st.warning(
            "🔒 Unsafe website detected."
        )


        # ====================================================
        # STREAMLIT CLOUD
        # ====================================================

        if not LOCAL_WINDOWS_MODE:

            st.info(
                "☁️ Streamlit Cloud deployment detected."
            )

            st.error(
                "🖥️ Kali Linux VM is not available "
                "from Streamlit Cloud."
            )

            st.write(
                "The AI detection and risk analysis "
                "are working normally, but the Kali "
                "Linux VM is running on your local "
                "Windows computer."
            )

            st.warning(
                "Run this application locally on Windows "
                "to open the unsafe website inside "
                "Kali Linux Chrome."
            )


        # ====================================================
        # LOCAL WINDOWS
        # ====================================================

        else:

            st.info(
                "The unsafe website will ONLY be opened "
                "inside Google Chrome in the Kali Linux "
                "VMware guest."
            )


            if st.button(
                "🖥️ Open Unsafe Website in Kali VM Chrome",
                type="primary",
                use_container_width=True,
                key="open_unsafe_vm_button",
            ):

                result = None


                # ============================================
                # STEP 1 - CHECK / START VM
                # ============================================

                with st.spinner(
                    "Starting/checking Kali Linux VM..."
                ):

                    if not vm_available():

                        st.info(
                            "🖥️ Kali VM is not running. "
                            "Trying to start VMware/Kali Linux..."
                        )


                        vm_start_result = (
                            start_kali_vm()
                        )


                        if not vm_start_result.get(
                            "success",
                            False,
                        ):

                            st.error(
                                "❌ Could not start "
                                "Kali Linux VM."
                            )

                            st.code(
                                vm_start_result.get(
                                    "message",
                                    "Unknown VM startup error.",
                                )
                            )

                        else:

                            st.success(
                                "✅ Kali Linux VM startup "
                                "command sent."
                            )


                    # ========================================
                    # STEP 2 - CHECK VM CONNECTION
                    # ========================================

                    if vm_available():

                        connection = (
                            get_vm_connection_status()
                        )


                        if not connection.get(
                            "connected",
                            False,
                        ):

                            st.warning(
                                "⚠️ Kali VM was detected, "
                                "but SSH connection is "
                                "not available."
                            )

                            st.code(
                                connection.get(
                                    "message",
                                    "Unknown SSH error.",
                                )
                            )


                        else:

                            # =================================
                            # STEP 3 - CHECK CHROME
                            # =================================

                            if not chrome_available():

                                st.error(
                                    "❌ Google Chrome was "
                                    "not found inside "
                                    "Kali Linux."
                                )


                            else:

                                # =============================
                                # STEP 4 - OPEN URL
                                # =============================

                                st.info(
                                    "🌐 Sending unsafe website "
                                    "to Google Chrome inside "
                                    "Kali Linux..."
                                )


                                result = (
                                    open_url_in_vm(
                                        analyzed_url
                                    )
                                )


                # =================================================
                # VM RESULT
                # =================================================

                if result is not None:

                    if result.get(
                        "success",
                        False,
                    ):

                        st.success(
                            "✅ Unsafe website opened "
                            "successfully inside Google "
                            "Chrome in Kali Linux VM."
                        )


                        # =========================================
                        # VMWARE FOREGROUND STATUS
                        # =========================================

                        vmware_focused = (
                            result.get(
                                "vmware_focused",
                                False,
                            )
                        )


                        if vmware_focused:

                            st.success(
                                "🖥️ VMware Workstation window "
                                "was automatically brought "
                                "to the foreground."
                            )

                        else:

                            st.warning(
                                "⚠️ Website opened in Kali Chrome, "
                                "but VMware Workstation could not "
                                "automatically be brought to the front."
                            )


                        # =========================================
                        # SECURITY MESSAGE
                        # =========================================

                        st.info(
                            "🔒 Windows normal browser "
                            "was NOT used."
                        )


                        # =========================================
                        # VM INFORMATION
                        # =========================================

                        st.write(
                            f"**VM:** "
                            f"`{result.get('vm_name', 'Kali Linux VM')}`"
                        )


                        st.write(
                            f"**Browser:** "
                            f"`{result.get('browser', 'Google Chrome')}`"
                        )


                        st.write(
                            f"**URL:** "
                            f"`{analyzed_url}`"
                        )


                        st.write(
                            f"**SSH:** "
                            f"`{result.get('ssh', 'N/A')}`"
                        )


                        # =========================================
                        # VM OUTPUT
                        # =========================================

                        if result.get(
                            "stdout"
                        ):

                            with st.expander(
                                "🖥️ VM Launch Output"
                            ):

                                st.code(
                                    result["stdout"]
                                )


                        if result.get(
                            "stderr"
                        ):

                            with st.expander(
                                "⚠️ VM Launch Messages"
                            ):

                                st.code(
                                    result["stderr"]
                                )


                    else:

                        st.error(
                            "❌ Failed to open website "
                            "in Kali VM."
                        )


                        st.code(
                            result.get(
                                "message",
                                "Unknown VM error.",
                            )
                        )


                        if result.get(
                            "stdout"
                        ):

                            st.write(
                                "**VM Output:**"
                            )

                            st.code(
                                result["stdout"]
                            )


                        if result.get(
                            "stderr"
                        ):

                            st.write(
                                "**VM Error:**"
                            )

                            st.code(
                                result["stderr"]
                            )


    # ========================================================
    # SAFE WEBSITE → NORMAL WINDOWS BROWSER
    # ========================================================

    else:

        st.success(
            "🟢 This website has a risk score "
            "below 25. Normal browser access is allowed."
        )


        if st.button(
            "🌐 Open Website in Normal Browser",
            use_container_width=True,
            key="open_safe_normal_browser_button",
        ):

            try:

                opened = webbrowser.open(
                    analyzed_url,
                    new=2,
                )


                if opened:

                    st.success(
                        "✅ Website opened in the "
                        "normal browser."
                    )

                else:

                    st.warning(
                        "⚠️ Browser launch command "
                        "was sent, but the browser "
                        "did not confirm the result."
                    )


            except Exception as e:

                st.error(
                    f"❌ Failed to open browser: {e}"
                )


    # ========================================================
    # DYNAMIC ANALYSIS
    # ========================================================

    st.divider()

    st.subheader(
        "⚡ Dynamic Analysis"
    )


    if DYNAMIC_AVAILABLE:

        st.caption(
            "Optional browser-level analysis can inspect "
            "redirects, JavaScript, forms and downloads."
        )


        if st.button(
            "⚡ Run Dynamic Analysis",
            use_container_width=True,
            key="dynamic_analysis_button",
        ):

            with st.spinner(
                "Running dynamic website analysis..."
            ):

                try:

                    dynamic_result = (
                        analyze_dynamic_url(
                            analyzed_url
                        )
                    )


                    st.session_state.dynamic = (
                        dynamic_result
                    )


                    st.rerun()


                except Exception as e:

                    st.error(
                        f"Dynamic analysis failed: {e}"
                    )


    else:

        st.info(
            "Dynamic analyzer is not currently available. "
            "Static 41-feature analysis is still active."
        )


    # ========================================================
    # 41 FEATURES
    # ========================================================

    with st.expander(
        "🔬 View all 41 extracted features"
    ):

        for index, feature_name in enumerate(
            FEATURE_NAMES,
            start=1,
        ):

            value = features.get(
                feature_name,
                0,
            )


            st.write(
                f"**{index}. {feature_name}:** "
                f"`{value}`"
            )


    # ========================================================
    # FEATURE VECTOR
    # ========================================================

    with st.expander(
        "🧮 View model feature vector"
    ):

        st.write(
            f"Feature count: "
            f"**{len(analysis['vector'])}**"
        )


        st.code(
            str(
                analysis["vector"]
            )
        )


    # ========================================================
    # VM DETAILS
    # ========================================================

    with st.expander(
        "🖥️ Kali VM Details"
    ):

        try:

            info = get_vm_info()

            st.json(
                info
            )

        except Exception as e:

            st.error(
                "Unable to retrieve VM information: "
                f"{e}"
            )


# ============================================================
# NO ANALYSIS YET
# ============================================================

else:

    st.info(
        "👆 Enter a website URL above and click "
        "**Analyze URL** to begin."
    )


# ============================================================
# FOOTER
# ============================================================

st.divider()

st.caption(
    "AI Browser Security • "
    "41-Feature Random Forest • "
    "Explainable Risk Scoring • "
    "Adaptive Browser Isolation"
)