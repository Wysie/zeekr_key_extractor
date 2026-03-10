# Zeekr Key Extractor

Extract the 6 secret values required by the [Zeekr Home Assistant integration](https://github.com/Fryyyyy/zeekr_homeassistant) and the [Zeekr EV API](https://github.com/Fryyyyy/zeekr_ev_api) library from the official Zeekr Android APK.

## Background

The Zeekr Home Assistant integration requires several secret values that are embedded in the Zeekr Android app. These values are used for API request signing, password encryption, and VIN encryption. Extracting them manually involves decompiling the APK with JADX and Ghidra, which can be a time-consuming process.

This tool automates the entire extraction process. It decompiles the DEX bytecode to find Java-level secrets and performs OLLVM deobfuscation on the native ARM64 libraries to decrypt the HMAC keys.

## Extracted Secrets

| Secret | Description | Source |
|---|---|---|
| HMAC Access Key | Used in `X-HMAC-ACCESS-KEY` header for API request signing | `libenv.so` (OLLVM-encrypted) |
| HMAC Secret Key | Used for HMAC-SHA256 signature computation | `libenv.so` (OLLVM-encrypted) |
| Password Public Key | RSA public key for encrypting the login password | DEX string table |
| Prod Secret | Used for `X-SIGNATURE` HMAC computation | DEX string table |
| VIN Key | AES-128-CBC key for encrypting the VIN in `X-VIN` header | DEX string table |
| VIN IV | AES-128-CBC initialization vector for VIN encryption | DEX string table |

## Requirements

- Python 3.10+
- An Android device (or emulator) with the Zeekr app installed
- ADB (Android Debug Bridge) for pulling the APK files

### Python Dependencies

```bash
pip install capstone pyelftools
```

## Usage

### Step 1: Pull the APK files from your device

Connect your Android device via USB (with USB debugging enabled) and run:

```bash
adb shell pm path com.zeekr.global
```

This will output something like:

```
package:/data/app/~~XXXX==/com.zeekr.global-YYYY==/base.apk
package:/data/app/~~XXXX==/com.zeekr.global-YYYY==/split_config.arm64_v8a.apk
package:/data/app/~~XXXX==/com.zeekr.global-YYYY==/split_config.xxhdpi.apk
```

Pull the two required files:

```bash
adb pull <path_to_base.apk> zeekr_base.apk
adb pull <path_to_arm64_v8a.apk> zeekr_arm64.apk
```

The `split_config.xxhdpi.apk` is not needed (it only contains density-specific resources).

### Step 2: Run the extractor

```bash
python zeekr_extract_secrets.py zeekr_base.apk zeekr_arm64.apk
```

The default region is **EM** (Emerging Markets), which covers most countries outside China and Europe (including Singapore, Australia, etc.). To specify a different region:

```bash
python zeekr_extract_secrets.py zeekr_base.apk zeekr_arm64.apk --region EU
```

Available regions:

| Region | Coverage |
|---|---|
| `CN` | China |
| `SEA` | Southeast Asia |
| `EU` | Europe |
| `EM` | Emerging Markets (default) |

> **Note:** The region flag only affects the HMAC Access Key and HMAC Secret Key. The other 4 secrets are the same across all regions. If you are unsure which region to use, try `EM` first — it works for most countries outside China and Europe. The HMAC keys must match the API gateway region, which may differ from the TSP region code used internally by the app.

### Step 3: Review the output

The script will print all 6 secrets and save them to a `zeekr_secrets.json` file in the same directory as the APK:

```
============================================================
  Zeekr APK Secret Extractor
  Target region: EM
============================================================
[1/4] Extracting DEX files from base APK...
      Found 15 DEX files
[2/4] Extracting native libraries...
      Found 24 native libraries
[3/4] Searching DEX files for secrets...
      [OK] Password Public Key (216 chars)
      [OK] Prod Secret: ********************************
      [OK] VIN Key: ****************
      [OK] VIN IV:  ****************
[4/4] Decrypting native library secrets (OLLVM deobfuscation)...
      [OK] HMAC Access Key: ********************************
      [OK] HMAC Secret Key: ****************************************

  All 6 secrets extracted successfully!
  Secrets saved to: zeekr_secrets.json
```

## Using the Secrets

### With the Home Assistant Integration

1. Install the [Zeekr integration](https://github.com/Fryyyyy/zeekr_homeassistant) via [HACS](https://hacs.xyz/).
2. Add the integration in Home Assistant (Settings > Devices & Services > Add Integration > Zeekr).
3. Enter your Zeekr account credentials and the 6 extracted secrets when prompted.

> **Tip:** Create a dedicated Zeekr account and share your car with it to avoid session conflicts with the phone app.

### With the Python API Library

```bash
pip install zeekr-ev-api
```

```python
from zeekr_ev_api.client import ZeekrClient

client = ZeekrClient(
    username="your_email",
    password="your_password",
    hmac_access_key="<from zeekr_secrets.json>",
    hmac_secret_key="<from zeekr_secrets.json>",
    password_public_key="<from zeekr_secrets.json>",
    prod_secret="<from zeekr_secrets.json>",
    vin_key="<from zeekr_secrets.json>",
    vin_iv="<from zeekr_secrets.json>",
)

client.login()
print("Login successful!")
print(client.get_vehicle_list())
```

## How It Works

The extractor uses two techniques to find the secrets:

1. **DEX string table scanning** — The base APK contains multiple DEX files (Dalvik bytecode). The script searches for specific byte patterns in the DEX string tables:
   - RSA public keys (base64-encoded, starting with `MIGfMA0GCSq`)
   - 32-character hex strings with ULEB128 length prefix (prod secret)
   - 16-character hex string pairs in DEX files containing `AES/CBC/PKCS5Padding` (VIN key and IV)

2. **OLLVM deobfuscation of native libraries** — The HMAC keys are stored in `libenv.so`, a native ARM64 library protected with [OLLVM](https://github.com/nickcano/OLLVM) string encryption. The script:
   - Disassembles the `.text` section using [Capstone](https://www.capstone-engine.org/)
   - Identifies the XOR decryption function by scanning for dense `EOR` instruction regions
   - Extracts all XOR operations (two patterns: `ldrb+mov+eor` and `ldrb+eor`)
   - Applies the XOR operations to decrypt the strings in-place
   - Maps the decrypted strings to the correct region/environment using the ELF relocation table

## Troubleshooting

**"HMAC Access Key: NOT FOUND"** — The script will print a list of candidate values. The OLLVM encryption pattern may have changed in a newer APK version. Try the candidates manually, or use JADX + Ghidra for manual inspection.

**"libenv.so not found"** — Make sure you provide the ARM64 split APK (`split_config.arm64_v8a.apk`) as the second argument. The native libraries are in this file, not in the base APK.

**Login fails with the extracted keys** — Try a different `--region` flag. The HMAC keys are region-specific and must match the API gateway your account connects to.

**APK version changes** — Zeekr may update the app and change how secrets are stored. If the script stops working after an app update, please open an issue.

## Disclaimer

This tool is provided for personal and educational use only. Use it at your own risk. The author is not affiliated with Zeekr or Geely. Reverse engineering may be subject to legal restrictions in your jurisdiction.

## License

MIT License. See [LICENSE](LICENSE) for details.

## Acknowledgments

- [Fryyyyy](https://github.com/Fryyyyy) for the [Zeekr Home Assistant integration](https://github.com/Fryyyyy/zeekr_homeassistant) and [Zeekr EV API](https://github.com/Fryyyyy/zeekr_ev_api) library
- [Capstone](https://www.capstone-engine.org/) for the disassembly framework
- [pyelftools](https://github.com/eliben/pyelftools) for ELF parsing
