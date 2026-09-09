import os
import subprocess
import time
import shlex
from pathlib import Path
from urllib.parse import urlparse


# ============================================================
# KALI LINUX VM SETTINGS
# ============================================================

VM_USER = "rajooriya"
VM_HOST = "192.168.29.129"

VM_SSH_TARGET = f"{VM_USER}@{VM_HOST}"

VM_DISPLAY = ":0"
VM_UID = "1000"

VM_XAUTHORITY = f"/home/{VM_USER}/.Xauthority"

CHROME_PATH = "/usr/bin/google-chrome"

SSH_TIMEOUT = 10


# ============================================================
# VMWARE SETTINGS
# ============================================================

# If automatic VMX detection does not find your Kali VM,
# put the complete .vmx path here.
#
# Example:
#
# VMX_PATH = r"C:\Users\Gourav\Documents\Virtual Machines\Kali Linux\Kali Linux.vmx"

VMX_PATH = None


VMWARE_EXE_CANDIDATES = [
    r"C:\Program Files (x86)\VMware\VMware Workstation\vmware.exe",
    r"C:\Program Files\VMware\VMware Workstation\vmware.exe",
]


VMRUN_EXE_CANDIDATES = [
    r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe",
    r"C:\Program Files\VMware\VMware Workstation\vmrun.exe",
]


VM_START_TIMEOUT = 120

VM_SSH_RETRY_INTERVAL = 3


# ============================================================
# WINDOWS PROCESS FLAGS
# ============================================================

if os.name == "nt":

    CREATE_NO_WINDOW = getattr(
        subprocess,
        "CREATE_NO_WINDOW",
        0,
    )

    CREATE_NEW_PROCESS_GROUP = getattr(
        subprocess,
        "CREATE_NEW_PROCESS_GROUP",
        0,
    )

else:

    CREATE_NO_WINDOW = 0
    CREATE_NEW_PROCESS_GROUP = 0


# ============================================================
# SSH BASE COMMAND
# ============================================================

def _vm_ssh_base_command():

    return [
        "ssh",

        "-o",
        "BatchMode=yes",

        "-o",
        "ConnectTimeout=8",

        "-o",
        "ConnectionAttempts=1",

        "-o",
        "ServerAliveInterval=5",

        "-o",
        "ServerAliveCountMax=1",

        "-o",
        "StrictHostKeyChecking=no",

        VM_SSH_TARGET,
    ]


# ============================================================
# SSH HELPER
# ============================================================

def run_ssh(
    remote_command: str,
    timeout: int = SSH_TIMEOUT,
):

    command = _vm_ssh_base_command()

    command.append(remote_command)

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=CREATE_NO_WINDOW,
        )

        return (
            result.returncode,
            (result.stdout or "").strip(),
            (result.stderr or "").strip(),
        )

    except subprocess.TimeoutExpired:

        return (
            -1,
            "",
            "SSH command timed out.",
        )

    except FileNotFoundError:

        return (
            -1,
            "",
            "Windows OpenSSH Client was not found.",
        )

    except Exception as exc:

        return (
            -1,
            "",
            str(exc),
        )


# ============================================================
# VM CONNECTION STATUS
# ============================================================

def get_vm_connection_status():

    code, stdout, stderr = run_ssh(
        "echo VM_OK",
        timeout=12,
    )

    if code == 0 and "VM_OK" in stdout:

        return {
            "connected": True,

            "message":
                "Successfully connected to Kali Linux VM.",

            "host": VM_HOST,

            "user": VM_USER,

            "ssh":
                VM_SSH_TARGET,
        }

    return {

        "connected": False,

        "message":
            stderr
            or stdout
            or "Unable to connect to Kali Linux VM.",

        "host": VM_HOST,

        "user": VM_USER,

        "ssh":
            VM_SSH_TARGET,
    }


# ============================================================
# CHECK VM CONNECTION
# ============================================================

def vm_available():

    status = get_vm_connection_status()

    return bool(
        status.get(
            "connected",
            False,
        )
    )


# ============================================================
# CHECK CHROME
# ============================================================

def chrome_available():

    code, stdout, stderr = run_ssh(

        "if command -v google-chrome >/dev/null 2>&1; "
        "then echo CHROME_OK; "

        "elif command -v google-chrome-stable >/dev/null 2>&1; "
        "then echo CHROME_OK; "

        "elif command -v chromium >/dev/null 2>&1; "
        "then echo CHROME_OK; "

        "elif command -v chromium-browser >/dev/null 2>&1; "
        "then echo CHROME_OK; "

        "else echo CHROME_NOT_FOUND; "

        "fi",

        timeout=12,
    )

    return (
        code == 0
        and "CHROME_OK" in stdout
    )


# ============================================================
# FIND VMWARE EXE
# ============================================================

def find_vmware_exe():

    for path in VMWARE_EXE_CANDIDATES:

        if Path(path).exists():

            return path

    return None


# ============================================================
# FIND VMRUN EXE
# ============================================================

def find_vmrun_exe():

    for path in VMRUN_EXE_CANDIDATES:

        if Path(path).exists():

            return path

    return None


# ============================================================
# FIND KALI VMX
# ============================================================

def find_kali_vmx():

    # --------------------------------------------------------
    # 1. Explicit VMX_PATH
    # --------------------------------------------------------

    if VMX_PATH:

        path = Path(VMX_PATH)

        if (
            path.exists()
            and path.suffix.lower() == ".vmx"
        ):

            return str(path)

    # --------------------------------------------------------
    # 2. Environment variable
    # --------------------------------------------------------

    env_path = os.environ.get(
        "KALI_VMX_PATH"
    )

    if env_path:

        path = Path(env_path)

        if (
            path.exists()
            and path.suffix.lower() == ".vmx"
        ):

            return str(path)

    # --------------------------------------------------------
    # 3. Search common VMware folders
    # --------------------------------------------------------

    home = Path.home()

    search_roots = [

        home
        / "Documents"
        / "Virtual Machines",

        home
        / "Documents",

        home
        / "OneDrive"
        / "Documents"
        / "Virtual Machines",

        home
        / "OneDrive"
        / "Documents",
    ]

    candidates = []

    for root in search_roots:

        if not root.exists():
            continue

        try:

            for vmx in root.rglob("*.vmx"):

                name = vmx.name.lower()

                parent = (
                    vmx.parent.name.lower()
                )

                text = (
                    f"{name} {parent}"
                )

                if (
                    "kali" in text
                    or "linux" in text
                ):

                    candidates.append(vmx)

        except Exception:

            continue

    if candidates:

        return str(
            candidates[0]
        )

    return None


# ============================================================
# GET VM INFORMATION
# ============================================================

def get_vm_info():

    info = {

        "available": False,

        "chrome_available": False,

        "user":
            VM_USER,

        "host":
            VM_HOST,

        "display":
            VM_DISPLAY,

        "xauthority":
            VM_XAUTHORITY,

        "ssh":
            VM_SSH_TARGET,

        "vmx_path":
            find_kali_vmx(),
    }

    info["available"] = vm_available()

    if info["available"]:

        info["chrome_available"] = (
            chrome_available()
        )

    return info


# ============================================================
# URL VALIDATION
# ============================================================

def validate_url(url: str):

    if not isinstance(
        url,
        str,
    ):

        raise ValueError(
            "URL must be a string."
        )

    url = url.strip()

    if not url:

        raise ValueError(
            "URL cannot be empty."
        )

    parsed = urlparse(url)

    if parsed.scheme.lower() not in (
        "http",
        "https",
    ):

        raise ValueError(
            "Only HTTP and HTTPS URLs are allowed."
        )

    if not parsed.netloc:

        raise ValueError(
            "Invalid URL."
        )

    return url


# ============================================================
# BRING VMWARE WORKSTATION TO FRONT
# ============================================================

def bring_vmware_to_front():

    """
    Restore VMware Workstation if minimized and bring
    its window to the foreground.

    This runs on Windows.

    It does NOT launch Chrome.

    Chrome is already running inside Kali Linux.
    """

    if os.name != "nt":

        return False

    try:

        powershell_script = r'''
Add-Type @"
using System;
using System.Runtime.InteropServices;

public class WindowHelper
{
    [DllImport("user32.dll")]
    public static extern bool SetForegroundWindow(
        IntPtr hWnd
    );

    [DllImport("user32.dll")]
    public static extern bool ShowWindow(
        IntPtr hWnd,
        int nCmdShow
    );

    [DllImport("user32.dll")]
    public static extern bool IsIconic(
        IntPtr hWnd
    );

    [DllImport("user32.dll")]
    public static extern bool IsWindowVisible(
        IntPtr hWnd
    );
}
"@

$windows = Get-Process vmware -ErrorAction SilentlyContinue |
    Where-Object {
        $_.MainWindowHandle -ne 0
    }

if (-not $windows)
{
    Write-Output "VMWARE_NOT_FOUND"
    exit 1
}

foreach ($process in $windows)
{
    $handle = $process.MainWindowHandle

    if ($handle -ne 0)
    {
        # SW_RESTORE = 9
        [WindowHelper]::ShowWindow(
            $handle,
            9
        ) | Out-Null

        Start-Sleep -Milliseconds 500

        [WindowHelper]::SetForegroundWindow(
            $handle
        ) | Out-Null

        Start-Sleep -Milliseconds 500

        # Try again to make sure it receives focus
        [WindowHelper]::SetForegroundWindow(
            $handle
        ) | Out-Null

        Write-Output "VMWARE_FOCUSED"

        exit 0
    }
}

Write-Output "VMWARE_NOT_FOUND"
exit 1
'''

        result = subprocess.run(

            [
                "powershell.exe",

                "-NoProfile",

                "-ExecutionPolicy",
                "Bypass",

                "-Command",
                powershell_script,
            ],

            capture_output=True,

            text=True,

            timeout=10,

            creationflags=CREATE_NO_WINDOW,
        )

        stdout = (
            result.stdout or ""
        ).strip()

        return (
            "VMWARE_FOCUSED"
            in stdout
        )

    except Exception:

        return False


# ============================================================
# WAIT AND BRING VMWARE TO FRONT
# ============================================================

def wait_and_bring_vmware_to_front(
    attempts=10,
    delay=0.5,
):

    """
    Sometimes VMware needs a little time to create
    its main window.

    This function retries several times.
    """

    for _ in range(attempts):

        if bring_vmware_to_front():

            return True

        time.sleep(delay)

    return False


# ============================================================
# START KALI VM
# ============================================================

def start_kali_vm():

    # --------------------------------------------------------
    # Check if already running
    # --------------------------------------------------------

    if vm_available():

        vmware_focused = (
            wait_and_bring_vmware_to_front()
        )

        return {

            "success": True,

            "started": False,

            "message":
                "Kali Linux VM is already running.",

            "vmware_focused":
                vmware_focused,
        }

    # --------------------------------------------------------
    # Find VMware
    # --------------------------------------------------------

    vmware_exe = (
        find_vmware_exe()
    )

    if not vmware_exe:

        return {

            "success": False,

            "started": False,

            "message":
                "VMware Workstation was not found.",
        }

    # --------------------------------------------------------
    # Find Kali VMX
    # --------------------------------------------------------

    vmx_path = (
        find_kali_vmx()
    )

    if not vmx_path:

        return {

            "success": False,

            "started": False,

            "message":
                (
                    "Kali Linux .vmx file was not found.\n\n"

                    "Set VMX_PATH in vm_launcher.py "
                    "to the complete path of your Kali "
                    ".vmx file."
                ),
        }

    # --------------------------------------------------------
    # Start VMware
    # --------------------------------------------------------

    try:

        subprocess.Popen(

            [
                vmware_exe,

                "-t",

                "ws",

                vmx_path,
            ],

            stdout=subprocess.DEVNULL,

            stderr=subprocess.DEVNULL,

            creationflags=(
                CREATE_NEW_PROCESS_GROUP
            ),
        )

    except Exception as exc:

        return {

            "success": False,

            "started": False,

            "message":
                (
                    "Failed to start VMware/Kali VM:\n"
                    f"{exc}"
                ),
        }

    # --------------------------------------------------------
    # Immediately try to show VMware
    # --------------------------------------------------------

    wait_and_bring_vmware_to_front(
        attempts=10,
        delay=0.5,
    )

    # --------------------------------------------------------
    # Wait for Kali SSH
    # --------------------------------------------------------

    start_time = time.time()

    while (

        time.time() - start_time
        < VM_START_TIMEOUT

    ):

        if vm_available():

            vmware_focused = (
                wait_and_bring_vmware_to_front(
                    attempts=10,
                    delay=0.5,
                )
            )

            return {

                "success": True,

                "started": True,

                "message":
                    "Kali Linux VM started successfully.",

                "vmx_path":
                    vmx_path,

                "vmware_focused":
                    vmware_focused,
            }

        time.sleep(
            VM_SSH_RETRY_INTERVAL
        )

    return {

        "success": False,

        "started": True,

        "message":
            (
                "VMware was opened, but Kali Linux "
                "did not become reachable through SSH "
                f"within {VM_START_TIMEOUT} seconds.\n\n"

                f"Expected SSH target: "
                f"{VM_SSH_TARGET}\n\n"

                "Make sure Kali is fully booted, "
                "logged in, and SSH is running."
            ),

        "vmx_path":
            vmx_path,
    }


# ============================================================
# WAIT FOR VM SSH
# ============================================================

def wait_for_vm(
    timeout=VM_START_TIMEOUT
):

    start_time = time.time()

    while (

        time.time() - start_time
        < timeout

    ):

        if vm_available():

            return True

        time.sleep(
            VM_SSH_RETRY_INTERVAL
        )

    return False


# ============================================================
# OPEN URL IN KALI CHROME
# ============================================================

def open_url_in_vm(url: str):
    """
    Open a URL visibly inside Google Chrome/Chromium
    running inside the Kali Linux VMware guest.

    IMPORTANT:
    This function does NOT open the URL in Windows Chrome,
    Edge, Firefox, Brave, etc.

    It uses SSH to execute Chrome inside Kali Linux.
    """

    # --------------------------------------------------------
    # Validate URL
    # --------------------------------------------------------

    try:

        url = validate_url(url)

    except Exception as exc:

        return {
            "success": False,
            "url": url,
            "message": str(exc),
        }

    # --------------------------------------------------------
    # Check Kali SSH connection
    # --------------------------------------------------------

    status = get_vm_connection_status()

    if not status.get(
        "connected",
        False,
    ):

        return {
            "success": False,
            "url": url,
            "message": (
                "Cannot connect to Kali Linux VM.\n\n"
                + status.get(
                    "message",
                    "Unknown SSH error.",
                )
            ),
            "vm_ip": VM_HOST,
            "vm_name": "Kali Linux VMware Guest",
            "browser": "Google Chrome",
            "ssh": VM_SSH_TARGET,
        }

    # --------------------------------------------------------
    # Check browser
    # --------------------------------------------------------

    browser_check_command = r"""
if command -v google-chrome >/dev/null 2>&1; then
    echo "CHROME_BIN:$(command -v google-chrome)"
elif command -v google-chrome-stable >/dev/null 2>&1; then
    echo "CHROME_BIN:$(command -v google-chrome-stable)"
elif command -v chromium >/dev/null 2>&1; then
    echo "CHROME_BIN:$(command -v chromium)"
elif command -v chromium-browser >/dev/null 2>&1; then
    echo "CHROME_BIN:$(command -v chromium-browser)"
else
    echo "CHROME_NOT_FOUND"
fi
"""

    code, stdout, stderr = run_ssh(
        browser_check_command,
        timeout=15,
    )

    if code != 0:

        return {
            "success": False,
            "url": url,
            "message": (
                stderr
                or stdout
                or "Could not check Chrome inside Kali."
            ),
            "vm_ip": VM_HOST,
            "ssh": VM_SSH_TARGET,
        }

    chrome_bin = None

    for line in stdout.splitlines():

        if line.startswith(
            "CHROME_BIN:"
        ):

            chrome_bin = line.split(
                ":",
                1,
            )[1].strip()

            break

    if not chrome_bin:

        return {
            "success": False,
            "url": url,
            "message": (
                "Google Chrome/Chromium was not found "
                "inside the Kali Linux VM."
            ),
            "vm_ip": VM_HOST,
            "ssh": VM_SSH_TARGET,
            "stdout": stdout,
            "stderr": stderr,
        }

    # --------------------------------------------------------
    # Safely quote URL
    # --------------------------------------------------------

    safe_url = shlex.quote(
        url
    )

    safe_chrome = shlex.quote(
        chrome_bin
    )

    safe_home = shlex.quote(
        f"/home/{VM_USER}"
    )

    safe_xauthority = shlex.quote(
        VM_XAUTHORITY
    )

    # --------------------------------------------------------
    # Remote GUI environment
    # --------------------------------------------------------

    remote_command = f"""
export HOME={safe_home};
export USER={shlex.quote(VM_USER)};
export LOGNAME={shlex.quote(VM_USER)};
export DISPLAY={shlex.quote(VM_DISPLAY)};
export XDG_RUNTIME_DIR={shlex.quote(f"/run/user/{VM_UID}")};

if [ -S /run/user/{VM_UID}/bus ]; then
    export DBUS_SESSION_BUS_ADDRESS="unix:path=/run/user/{VM_UID}/bus";
fi;

if [ -f {safe_xauthority} ]; then
    export XAUTHORITY={safe_xauthority};
fi;

mkdir -p /tmp/ai_browser_security;
mkdir -p /tmp/ai_browser_security/visible-profile;

# ----------------------------------------------------------
# Check X display
# ----------------------------------------------------------

if ! command -v xdpyinfo >/dev/null 2>&1; then
    echo "DISPLAY_CHECK_SKIPPED";
else
    if xdpyinfo >/dev/null 2>&1; then
        echo "DISPLAY_OK";
    else
        echo "DISPLAY_NOT_AVAILABLE";
    fi;
fi;

# ----------------------------------------------------------
# Launch visible Chrome in Kali
# ----------------------------------------------------------

nohup {safe_chrome} \
    --user-data-dir=/tmp/ai_browser_security/visible-profile \
    --new-window \
    --no-first-run \
    --no-default-browser-check \
    --disable-session-crashed-bubble \
    --disable-features=Translate \
    --noerrdialogs \
    --disable-infobars \
    {safe_url} \
    >/tmp/ai_browser_security/visible_chrome.log \
    2>&1 </dev/null &

CHROME_PID=$!

echo "CHROME_PID:$CHROME_PID";

sleep 3;

if kill -0 "$CHROME_PID" >/dev/null 2>&1; then
    echo "VM_CHROME_STARTED";
else
    echo "VM_CHROME_PROCESS_EXITED";
fi;

echo "CHROME_LOG_BEGIN";

tail -50 /tmp/ai_browser_security/visible_chrome.log 2>/dev/null || true;

echo "CHROME_LOG_END";
"""

    # --------------------------------------------------------
    # Execute command through SSH
    # --------------------------------------------------------

    command = _vm_ssh_base_command()

    command.append(
        remote_command
    )

    try:

        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=35,
            creationflags=CREATE_NO_WINDOW,
        )

        stdout = (
            result.stdout or ""
        ).strip()

        stderr = (
            result.stderr or ""
        ).strip()

        # ----------------------------------------------------
        # SSH failure
        # ----------------------------------------------------

        if result.returncode != 0:

            return {
                "success": False,
                "url": url,
                "message": (
                    stderr
                    or stdout
                    or (
                        "Failed to execute Chrome "
                        "inside Kali Linux."
                    )
                ),
                "vm_ip": VM_HOST,
                "vm_name": "Kali Linux VMware Guest",
                "browser": "Google Chrome",
                "ssh": VM_SSH_TARGET,
                "stdout": stdout,
                "stderr": stderr,
            }

        # ----------------------------------------------------
        # Chrome successfully launched
        # ----------------------------------------------------

        if "VM_CHROME_STARTED" in stdout:

            # Give Kali display a moment to update.
            time.sleep(1)

            # Bring VMware to foreground.
            vmware_focused = (
                wait_and_bring_vmware_to_front(
                    attempts=12,
                    delay=0.5,
                )
            )

            return {
                "success": True,
                "url": url,
                "message": (
                    "Website successfully opened inside "
                    "Google Chrome in the Kali Linux VM."
                ),
                "vm_ip": VM_HOST,
                "vm_name": "Kali Linux VMware Guest",
                "browser": (
                    "Google Chrome "
                    "(Kali Linux VM)"
                ),
                "ssh": VM_SSH_TARGET,
                "chrome_path": chrome_bin,
                "stdout": stdout,
                "stderr": stderr,
                "vmware_focused": vmware_focused,
            }

        # ----------------------------------------------------
        # Chrome process did not remain alive
        # ----------------------------------------------------

        if "VM_CHROME_PROCESS_EXITED" in stdout:

            return {
                "success": False,
                "url": url,
                "message": (
                    "Chrome launch command was sent to Kali, "
                    "but the Chrome process exited immediately. "
                    "Check the Chrome log below."
                ),
                "vm_ip": VM_HOST,
                "vm_name": "Kali Linux VMware Guest",
                "browser": (
                    "Google Chrome "
                    "(Kali Linux VM)"
                ),
                "ssh": VM_SSH_TARGET,
                "chrome_path": chrome_bin,
                "stdout": stdout,
                "stderr": stderr,
            }

        # ----------------------------------------------------
        # Unknown result
        # ----------------------------------------------------

        return {
            "success": False,
            "url": url,
            "message": (
                "SSH command completed, but Chrome "
                "could not be confirmed as running."
            ),
            "vm_ip": VM_HOST,
            "vm_name": "Kali Linux VMware Guest",
            "browser": (
                "Google Chrome "
                "(Kali Linux VM)"
            ),
            "ssh": VM_SSH_TARGET,
            "chrome_path": chrome_bin,
            "stdout": stdout,
            "stderr": stderr,
        }

    except subprocess.TimeoutExpired:

        return {
            "success": False,
            "url": url,
            "message": (
                "SSH/Chrome launch timed out "
                "after 35 seconds."
            ),
            "vm_ip": VM_HOST,
            "vm_name": "Kali Linux VMware Guest",
            "browser": "Google Chrome",
            "ssh": VM_SSH_TARGET,
        }

    except FileNotFoundError:

        return {
            "success": False,
            "url": url,
            "message": (
                "Windows OpenSSH Client was not found."
            ),
            "ssh": VM_SSH_TARGET,
        }

    except Exception as exc:

        return {
            "success": False,
            "url": url,
            "message": str(exc),
            "ssh": VM_SSH_TARGET,
        }


# ============================================================
# COMMAND LINE TEST
# ============================================================

def test_vm_connection():

    print("=" * 60)

    print(
        "KALI VM CONNECTION TEST"
    )

    print("=" * 60)

    print(
        f"VM: {VM_SSH_TARGET}"
    )

    vmx = (
        find_kali_vmx()
    )

    print(
        f"VMX: {vmx}"
    )

    status = (
        get_vm_connection_status()
    )

    if status.get(
        "connected",
        False,
    ):

        print(
            "[OK] SSH connection successful"
        )

    else:

        print(
            "[ERROR] Cannot connect to Kali VM"
        )

        print(
            status.get(
                "message",
                "",
            )
        )

        return False

    if chrome_available():

        print(
            "[OK] Google Chrome detected"
        )

    else:

        print(
            "[ERROR] Google Chrome not detected"
        )

        return False

    print(
        "[OK] VM is ready"
    )

    print("=" * 60)

    return True


# ============================================================
# DIRECT TEST
# ============================================================

if __name__ == "__main__":

    print()

    print(
        "Testing Kali Linux VM..."
    )

    print()

    if test_vm_connection():

        test_url = (
            "https://example.com"
        )

        print()

        print(
            "Opening URL:"
        )

        print(
            test_url
        )

        result = (
            open_url_in_vm(
                test_url
            )
        )

        print()

        print(
            "RESULT:"
        )

        print(
            result
        )


# ============================================================
# HEADLESS KALI WEBSITE SCANNER
# ============================================================

def scan_url_in_vm(
    url: str,
    timeout: int = 45
):
    """
    Render a website inside Kali Linux using the Chrome/Chromium
    headless engine.

    No Windows browser is opened.
    No visible Chrome window is required.

    The rendered DOM is returned to the Windows application.
    """

    import json
    import shlex

    # --------------------------------------------------------
    # Validate
    # --------------------------------------------------------

    if not isinstance(url, str):
        raise ValueError(
            "URL must be a string."
        )

    url = url.strip()

    if not url:
        raise ValueError(
            "URL is empty."
        )

    safe_url = shlex.quote(
        url
    )

    # --------------------------------------------------------
    # Check VM
    # --------------------------------------------------------

    status = get_vm_connection_status()

    if not status.get(
        "connected",
        False
    ):

        return {
            "available": False,
            "success": False,
            "error":
                status.get(
                    "message",
                    "Kali VM is not reachable."
                ),
        }

    # --------------------------------------------------------
    # Remote command
    # --------------------------------------------------------

    remote_command = f"""
set -u

URL={safe_url}

TMP_DIR="/tmp/ai_browser_security"
PROFILE="$TMP_DIR/headless-profile"

mkdir -p "$TMP_DIR"
rm -rf "$PROFILE"
mkdir -p "$PROFILE"

CHROME_BIN="$(command -v google-chrome || \
command -v google-chrome-stable || \
command -v chromium || \
command -v chromium-browser || true)"

if [ -z "$CHROME_BIN" ]; then
    echo "ERROR:CHROME_NOT_FOUND"
    exit 20
fi

timeout {int(timeout)}s "$CHROME_BIN" \
    --headless=new \
    --disable-gpu \
    --no-sandbox \
    --disable-dev-shm-usage \
    --disable-extensions \
    --disable-background-networking \
    --disable-sync \
    --disable-default-apps \
    --disable-popup-blocking \
    --no-first-run \
    --no-default-browser-check \
    --user-data-dir="$PROFILE" \
    --virtual-time-budget=8000 \
    --dump-dom \
    "$URL" \
    2>/tmp/ai_browser_security/chrome_error.txt \
    > /tmp/ai_browser_security/rendered.html

STATUS=$?

echo "EXIT_CODE:$STATUS"

if [ -f /tmp/ai_browser_security/rendered.html ]; then
    echo "HTML_BEGIN"
    cat /tmp/ai_browser_security/rendered.html
    echo
    echo "HTML_END"
fi

if [ -f /tmp/ai_browser_security/chrome_error.txt ]; then
    echo "ERROR_BEGIN"
    tail -100 /tmp/ai_browser_security/chrome_error.txt
    echo
    echo "ERROR_END"
fi

rm -rf "$PROFILE"
"""

    # --------------------------------------------------------
    # Execute
    # --------------------------------------------------------

    code, stdout, stderr = run_ssh(
        remote_command,
        timeout=timeout + 15
    )

    if code != 0:

        return {
            "available": True,
            "success": False,
            "error":
                stderr
                or stdout
                or (
                    "Headless Chrome "
                    "scan failed."
                ),
        }

    # --------------------------------------------------------
    # Extract HTML
    # --------------------------------------------------------

    html = ""

    if "HTML_BEGIN" in stdout:

        try:

            html = (
                stdout
                .split(
                    "HTML_BEGIN",
                    1
                )[1]
                .split(
                    "HTML_END",
                    1
                )[0]
                .strip()
            )

        except Exception:
            html = ""

    # --------------------------------------------------------
    # Extract exit code
    # --------------------------------------------------------

    exit_code = None

    for line in stdout.splitlines():

        if line.startswith(
            "EXIT_CODE:"
        ):

            try:

                exit_code = int(
                    line.split(
                        ":",
                        1
                    )[1]
                )

            except Exception:
                pass

            break

    if not html:

        return {
            "available": True,
            "success": False,
            "exit_code": exit_code,
            "error":
                "Chrome completed but "
                "no rendered HTML was returned.",
        }

    return {
        "available": True,
        "success": True,
        "exit_code": exit_code,
        "url": url,
        "final_url": url,
        "html": html,
        "html_size": len(html),
        "message":
            "Website rendered successfully "
            "inside Kali headless Chrome.",
    }