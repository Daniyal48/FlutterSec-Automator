# FlutterSec-Automator

[![Python 3.10+](https://img.shields.io/badge/Python-3.10%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Code style: Ruff](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/astral-sh/ruff/main/assets/badge/v2.json)](https://github.com/astral-sh/ruff)

**FlutterSec-Automator** is an advanced dynamic analysis utility designed to streamline mobile application security assessments by identifying targets for runtime instrumentation within Flutter binaries (Android APK & iOS IPA).

By automating the extraction, parsing, and ahead-of-time (AOT) structural analysis of the native library (`libflutter.so`), FlutterSec-Automator locates specific subroutines within the underlying networking stack (`BoringSSL`) to generate targeted [Frida](https://frida.re/) scripts. This helps security researchers analyze application layer communication boundaries without time-consuming manual structural scanning.

---

## ⚡ Features

- **Zero-Touch Analysis:** Automatically extracts and manages `libflutter.so` from compressed APK/IPA archives.
- **AOT Architecture Scanning:** Accurately identifies the embedded Flutter Engine build hash and dynamically discovers native `BoringSSL` offsets via memory pattern matching.
- **Dynamic Script Synthesis:** Outputs ready-to-use JavaScript instrumentation payloads tailored for deployment via `frida-server` or `frida-gadget`.
- **Multi-Architecture:** Supports standard ARM architectures (`arm64-v8a`, `x86_64`).
- **Flexible Core:** Robust architecture supporting custom manual offset injection overrides when handling non-standard or heavily optimized engine builds.

---

## 🛠 Installation

### Prerequisites

- Python 3.10 or higher.
- An authorized testing device or emulator configured with [frida-server](https://frida.re/docs/android/).

### Setup

Clone the repository and install the project dependencies.

```bash
git clone https://github.com/Daniyal48/FlutterSec-Automator.git
cd FlutterSec-Automator

# Create a virtual environment
python -m venv venv

# Activate the virtual environment

# Linux/macOS
source venv/bin/activate

# Windows (PowerShell)
venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Alternatively, install in editable mode
pip install -e .
```

---

## 🚀 Basic Usage

Execute the analysis engine against a target application package to discover execution reference targets and generate a Frida instrumentation payload.

### Analyze an Android APK

```bash
fluttersec analyze \
    --apk /path/to/target_app.apk \
    --output-dir ./output/
```

### Analyze an iOS IPA

> **Note:** Full IPA extraction requires a macOS host.

```bash
fluttersec analyze \
    --ipa /path/to/target_app.ipa \
    --output-dir ./output/
```

---

## 📦 Deploying the Generated Payload

The generated JavaScript payload (for example, `com_example_app_frida_bypass.js`) can be injected using Frida.

```bash
frida -U \
    -f com.example.app \
    -l ./output/com_example_app_frida_bypass.js \
    --no-pause
```

---

## 🔍 Advanced Usage: Manual Offset Override (Ghidra Workflow)

When analyzing applications built with heavily optimized or customized Flutter engines, automated pattern matching may not always locate the desired BoringSSL routines. In such cases, you can manually determine the function offset using Ghidra and provide it with the `--offset` option.

### Step 1 — Extract the Shared Library

Extract the APK and locate the target library:

```
lib/arm64-v8a/libflutter.so
```

---

### Step 2 — Import into Ghidra

1. Create a new Ghidra project.
2. Import `libflutter.so`.
3. Open the binary in **CodeBrowser**.
4. Run the default auto-analysis.

---

### Step 3 — Locate the SSL String

Navigate to:

```
Search → Program Text
```

(or)

```
Window → Defined Strings
```

Search for:

```
ssl_client
```

Open the matching string inside the `.rodata` section.

---

### Step 4 — Follow Cross References

1. Right-click the `"ssl_client"` string.
2. Select:

```
References → Show References to Address
```

3. Double-click one of the references to jump into the calling function.

---

### Step 5 — Determine the Function Offset

Scroll to the beginning of the function (typically beginning with instructions similar to):

```asm
STP X29, X30, [SP, #-N]!
```

Record the function start address.

For example:

```
0x001A4BC0
```

Subtract the image base (commonly `0x100000` or `0x0`) to obtain the relative offset.

```
Relative Offset = Function Address - Image Base
```

Example:

```
Function Address : 0x001A4BC0
Image Base       : 0x00100000
Relative Offset  : 0x000A4BC0
```

---

### Step 6 — Supply the Offset

Provide the discovered offset directly to the analysis engine.

```bash
fluttersec analyze \
    --apk /path/to/target_app.apk \
    --offset 0x1A4BC0 \
    --output-dir ./output/
```

Using `--offset` bypasses automatic pattern discovery and instructs FlutterSec-Automator to generate the Frida script using the supplied address.

---

## ⚖️ Legal Disclaimer

FlutterSec-Automator is provided solely for **educational purposes, security research, and authorized security assessments**.

This project is intended for use by security professionals, developers, and QA engineers when testing software that they own or are explicitly authorized to assess. Unauthorized use against systems or applications without prior written permission may violate applicable laws and regulations.

The authors and maintainers assume **no responsibility or liability** for misuse of this software or for any consequences arising from unauthorized or illegal activities.