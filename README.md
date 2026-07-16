# FlutterSec-Automator

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**FlutterSec-Automator** is an advanced dynamic analysis tool designed to automatically bypass SSL pinning in Flutter applications (Android APK & iOS IPA). 

By automating the extraction, parsing, and AOT binary analysis of the Dart native library (`libflutter.so`), FlutterSec-Automator dynamically generates highly targeted [Frida](https://frida.re/) scripts. These scripts inject native C hooks into the `BoringSSL` engine, intercepting `ssl_verify_peer_cert` and neutralizing network layer security checks without requiring time-consuming manual reverse engineering.

---

## ⚡ Features

*   **Zero-Touch Analysis:** Automatically extracts and analyzes `libflutter.so` from compressed APK/IPA files.
*   **AOT Binary Scanning:** Accurately identifies the Flutter Engine hash and dynamically discovers native `BoringSSL` offsets via memory pattern matching.
*   **Dynamic Script Generation:** Automatically constructs ready-to-run `.js` payloads injected via `frida-server` or `frida-gadget`.
*   **Multi-Architecture:** Supports standard ARM architectures (`arm64-v8a`, `x86_64`).

---

## 🛠 Installation

### Prerequisites
*   Python 3.10 or higher.
*   A rooted Android device or emulator running [frida-server](https://frida.re/docs/android/).

### Setup
Clone the repository and install the required dependencies:

```bash
git clone https://github.com/yourusername/FlutterSec-Automator.git
cd FlutterSec-Automator

# Create a virtual environment
python -m venv venv

# Activate the virtual environment
# On Linux/macOS:
source venv/bin/activate
# On Windows:
venv\Scripts\activate

# Install requirements
pip install -r requirements.txt
# Alternatively, install as a package
pip install -e .
```

---

## 🚀 Usage

Execute the tool against a target application to generate the bypass payload:

```bash
# Analyze an Android APK
fluttersec analyze --apk /path/to/target_app.apk --output-dir ./bypass_scripts/

# Analyze an iOS IPA (Requires macOS environment)
fluttersec analyze --ipa /path/to/target_app.ipa --output-dir ./bypass_scripts/
```

### Injecting the Payload

The tool will generate a custom script (e.g., `com_example_app_bypass.js`). Deploy it dynamically using Frida:

```bash
# Connect to USB device and inject the script into the running application
frida -U -f com.example.app -l ./bypass_scripts/com_example_app_bypass.js --no-pause
```

---

## ⚖️ Legal Disclaimer

**FlutterSec-Automator is built for educational and authorized security testing purposes only.** 

This tool is intended to assist security researchers, penetration testers, and developers in analyzing their own applications or systems where explicit, documented authorization has been granted. Do not use this tool on targets you do not own or have permission to test. The authors and maintainers assume no liability and are not responsible for any misuse, damage, or legal consequences caused by the utilization of this software.
