#!/usr/bin/env python3

import os
import sys
import json
import hmac
import time
import logging
import hashlib
import platform
import subprocess
import zipfile
import urllib.request
from typing import Optional
from base64 import b64encode, b64decode
from urllib.parse import urlparse
from Cryptodome.Cipher import AES
from Cryptodome.Util.Padding import unpad
import requests

# Constants
VERSION = "1.0"
AES_KEY = b"20nr1aobv2xi8ax4"
AES_IV = b"0102030405060708"
HMAC_KEY = "10f29ff413c89c8de02349cb3eb9a5f510f29ff413c89c8de02349cb3eb9a5f5"
UNLOCK_URLS = {
    "global": "https://unlock.update.intl.miui.com/v1/unlock/applyBind",
    "china": "https://unlock.update.miui.com/v1/unlock/applyBind"
}
SETTINGS_APK_URL = "https://github.com/bluebeard9998/MicomDetour/releases/download/settings-app/Settings.apk.zip"

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(levelname)s: %(message)s")
logger = logging.getLogger(__name__)

def install_dependencies():
    """Install required Python dependencies if missing."""
    for lib, pip_name in [("Cryptodome", "pycryptodomex"), ("requests", "requests")]:
        try:
            __import__(lib)
        except ImportError:
            logger.info(f"Installing {pip_name}...")
            subprocess.check_call([sys.executable, "-m", "pip", "install", pip_name])

def download_platform_tools(os_type: str) -> str:
    """Download and extract Android platform-tools for the given OS."""
    base_dir = os.path.dirname(os.path.abspath(__file__))
    url = f"https://dl.google.com/android/repository/platform-tools-latest-{os_type}.zip"
    zip_path = os.path.join(base_dir, os.path.basename(url))
    tools_dir = os.path.join(base_dir, "platform-tools")

    if not os.path.exists(tools_dir):
        logger.info("Downloading platform-tools...\nWait until it ends & then run the script again")
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, "r") as zip_ref:
            zip_ref.extractall(base_dir)
        os.remove(zip_path)
    return os.path.join(tools_dir, "adb")

def check_device_connected(adb_path: str) -> bool:
    """Check if an Android device is connected via ADB."""
    for _ in range(5):  # Retry 5 times
        try:
            result = subprocess.run([adb_path, "get-state"], capture_output=True, text=True, timeout=6)
            if "device" in result.stdout:
                return True
            time.sleep(2)
        except subprocess.TimeoutExpired:
            logger.warning("ADB command timed out, retrying...")
    return False

def get_device_region(adb_path: str) -> str:
    """Determine if the device is global or China based on model."""
    result = subprocess.check_output([adb_path, "shell", "getprop", "ro.product.mod_device"], timeout=10)
    return "global" if "_global" in result.decode("utf-8").strip() else "china"

def execute_adb_commands(adb_path: str):
    """Execute preparatory ADB commands on the device."""
    commands = [
        [adb_path, "logcat", "-c"],
        [adb_path, "shell", "svc", "wifi", "disable"],
        [adb_path, "shell", "svc", "data", "enable"],
        [adb_path, "shell", "am", "start", "--activity-clear-task", "-a", "android.settings.APPLICATION_DEVELOPMENT_SETTINGS"]
    ]
    for cmd in commands:
        subprocess.run(cmd, check=True, timeout=10)

def capture_logcat(adb_path: str) -> tuple[Optional[str], Optional[str]]:
    """Capture and parse logcat for CloudDeviceStatus args and headers."""
    logger.info("Waiting for account binding data in logcat...")
    for _ in range(30):  # Poll for up to 5 minutes (30 * 10s)
        result = subprocess.check_output([adb_path, "logcat", "*:S", "CloudDeviceStatus:V", "-d"], timeout=10)
        output = result.decode("utf-8").splitlines()
        args, headers = None, None
        for line in output:
            if "CloudDeviceStatus: args:" in line:
                args = line.split("args:")[1].strip()
            if "CloudDeviceStatus: headers:" in line:
                headers = line.split("headers:")[1].strip()
            if args and headers:
                subprocess.run([adb_path, "shell", "svc", "data", "disable"], timeout=10)
                return args, headers
        time.sleep(10)
    logger.error("Failed to capture logcat data.")
    return None, None

def decrypt_data(args: str, headers: str) -> tuple[dict, dict]:
    """Decrypt logcat args and headers using AES."""
    try:
        cipher = AES.new(AES_KEY, AES.MODE_CBC, AES_IV)
        decrypted_args = unpad(cipher.decrypt(b64decode(args)), AES.block_size).decode("utf-8")
        decrypted_headers = cipher.decrypt(b64decode(headers)).rstrip(b"\0").decode("utf-8")
        cookie = re.search(r"Cookie=\[(.*)\]", decrypted_headers).group(1).strip()
        return json.loads(decrypted_args), {"Cookie": cookie, "Content-Type": "application/x-www-form-urlencoded"}
    except Exception as e:
        logger.error(f"Decryption failed: {e}")
        logger.info(f"Try downgrading Settings app: {SETTINGS_APK_URL}")
        sys.exit(1)

def bypass_hyperos_restriction(data: dict) -> dict:
    """Modify ROM version to bypass HyperOS restrictions."""
    if data.get("rom_version", "").startswith("V816"):
        logger.info(f"Current version: {data['rom_version']}")
        data["rom_version"] = data["rom_version"].replace("V816", "V14")
        logger.info(f"Version updated to: {data['rom_version']}")
    return data

def generate_signature(data: str) -> str:
    """Generate HMAC-SHA1 signature for the request."""
    message = f"POST\n/v1/unlock/applyBind\ndata={data}&sid=miui_sec_android".encode("utf-8")
    return hmac.new(HMAC_KEY.encode("utf-8"), message, hashlib.sha1).hexdigest()

def send_unlock_request(url: str, data: dict, headers: dict):
    """Send the binding request to Xiaomi's unlock server."""
    payload = {
        "data": json.dumps(data),
        "sid": "miui_sec_android",
        "sign": generate_signature(json.dumps(data))
    }
    response = requests.post(url, data=payload, headers=headers, timeout=10)
    response.raise_for_status()
    return response.json()

def main():
    """Main function to orchestrate the unlocking process."""
    install_dependencies()
    os_type = platform.system().lower()
    adb_path = download_platform_tools(os_type)

    if not check_device_connected(adb_path):
        logger.error("No device connected. Exiting...")
        sys.exit(1)
    logger.info("\nFor feedback:\n- GitHub: https://github.com/bluebeard9998\n- Intagram: @ranjbar.ed1998")
    logger.info("Device connected successfully.")

    region = get_device_region(adb_path)
    url = UNLOCK_URLS[region]
    execute_adb_commands(adb_path)
    logger.info("Now bind your account in Mi Unlock status...")

    args, headers = capture_logcat(adb_path)
    if not (args and headers):
        sys.exit(1)

    data, headers = decrypt_data(args, headers)
    data = bypass_hyperos_restriction(data)
    response = send_unlock_request(url, data, headers)

    if "code" in response:
        if response["code"] == 0:
            logger.info("Linked successfully!")
        elif response["code"] == 401:
            logger.warning("Code 401: Parameter expired. Log out and log in again.")
        elif response["code"] == 30001:
            logger.error("Code 30001: Device forced to verify, cannot unlock.")
        else:
            logger.info(f"Response: {response}")
    else:
        logger.info(f"Unexpected response: {response}")

    if os_type == "windows":
        input("Press Enter to exit...")

if __name__ == "__main__":
    main()