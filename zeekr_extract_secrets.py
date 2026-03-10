#!/usr/bin/env python3
"""
Zeekr APK Secret Extractor
===========================
Extracts the 6 secrets required for the Zeekr Home Assistant integration
(https://github.com/Fryyyyy/zeekr_homeassistant) from the Zeekr Android APK files.

Requirements:
    pip install capstone pyelftools

Usage:
    python zeekr_extract_secrets.py <base.apk> [arm64.apk]

    - base.apk:  The main Zeekr APK (com.zeekr.global)
    - arm64.apk: The ARM64 split APK (optional, will look for .so in base if not provided)

To pull APKs from a device:
    adb shell pm path com.zeekr.global
    adb pull <path_to_base.apk> zeekr_base.apk
    adb pull <path_to_arm64.apk> zeekr_arm64.apk
"""

import argparse
import json
import os
import re
import struct
import sys
import tempfile
import zipfile
from pathlib import Path

try:
    from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
except ImportError:
    print("ERROR: capstone is required. Install with: pip install capstone")
    sys.exit(1)

try:
    from elftools.elf.elffile import ELFFile
except ImportError:
    print("ERROR: pyelftools is required. Install with: pip install pyelftools")
    sys.exit(1)


# ============================================================================
# Constants
# ============================================================================

# Region indices in the pointer tables (4 regions per environment group)
REGION_INDICES = {"CN": 0, "SEA": 1, "EU": 2, "EM": 3}
REGIONS_PER_ENV = 4

# The PROD environment is at group index 1 in the pointer tables
# Table order: DEV=0, PROD=1, UAT=2, SIT=3, PREPROD=4, ...
PROD_ENV_GROUP = 1

# Known non-secret 16-char hex strings to filter out
TRIVIAL_HEX16 = {
    "0000000000000000",
    "0123456789012345",
    "0123456789abcdef",
    "9774d56d682e549c",
}


# ============================================================================
# Native Library Analyzer (for OLLVM-encrypted secrets in .so files)
# ============================================================================

class NativeLibAnalyzer:
    """Analyze ARM64 native libraries to decrypt OLLVM-encrypted strings."""

    def __init__(self, so_path: str):
        self.so_path = so_path
        with open(so_path, "rb") as f:
            self.data = f.read()
        self._parse_elf()

    def _parse_elf(self):
        """Parse ELF segments and relocations."""
        with open(self.so_path, "rb") as f:
            elf = ELFFile(f)
            self.segments = []
            for seg in elf.iter_segments():
                if seg.header.p_type == "PT_LOAD":
                    self.segments.append(
                        (
                            seg.header.p_vaddr,
                            seg.header.p_offset,
                            seg.header.p_filesz,
                            seg.header.p_memsz,
                        )
                    )

            self.relocs = {}
            for section in elf.iter_sections():
                if section.header.sh_type in ("SHT_RELA", "SHT_REL"):
                    for rel in section.iter_relocations():
                        self.relocs[rel["r_offset"]] = rel.entry.get("r_addend", 0)

    def vaddr_to_offset(self, vaddr: int) -> int | None:
        """Convert virtual address to file offset."""
        for seg_vaddr, seg_offset, seg_filesz, seg_memsz in self.segments:
            if seg_vaddr <= vaddr < seg_vaddr + seg_memsz:
                off = vaddr - seg_vaddr + seg_offset
                if off < seg_offset + seg_filesz:
                    return off
        return None

    def decrypt_strings(self) -> dict:
        """Decrypt all OLLVM-encrypted strings using ARM64 disassembly.

        Returns a dict mapping virtual address -> decrypted string.
        """
        code_end = 0
        for seg_vaddr, seg_offset, seg_filesz, seg_memsz in self.segments:
            if seg_offset == 0:
                code_end = seg_filesz
                break

        if code_end == 0:
            return {}

        md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        md.detail = True

        # Find the XOR init function by scanning for dense EOR regions
        best_offset = None
        best_density = 0
        chunk_size = 0x200

        for offset in range(0, min(code_end, len(self.data)) - chunk_size, 0x100):
            chunk = self.data[offset : offset + chunk_size]
            eor_count = sum(1 for i in md.disasm(chunk, offset) if i.mnemonic == "eor")
            density = eor_count / (chunk_size / 4)
            if density > best_density:
                best_density = density
                best_offset = offset

        if best_offset is None or best_density < 0.05:
            return {}

        # Walk backward to find function prologue
        func_start = best_offset
        for offset in range(best_offset, max(0, best_offset - 0x1000), -4):
            word = struct.unpack_from("<I", self.data, offset)[0]
            if (word & 0xFFE00000) == 0xA9800000:
                func_start = offset
                break

        func_data = self.data[func_start:code_end]
        instructions = list(md.disasm(func_data, func_start))

        # Extract XOR operations from two instruction patterns
        xor_ops = []
        current_base = None

        for i in range(len(instructions)):
            insn = instructions[i]

            if insn.mnemonic == "adr" and len(insn.operands) == 2:
                current_base = insn.operands[1].imm
                continue

            if insn.mnemonic == "adrp" and i + 1 < len(instructions):
                next_insn = instructions[i + 1]
                if next_insn.mnemonic == "add":
                    current_base = insn.operands[1].imm + next_insn.operands[2].imm
                    continue

            # Pattern 1: ldrb + mov + eor
            if (
                insn.mnemonic == "ldrb"
                and i + 2 < len(instructions)
                and instructions[i + 1].mnemonic == "mov"
                and instructions[i + 2].mnemonic == "eor"
            ):
                mem = insn.operands[1]
                if mem.type == 3 and current_base is not None:
                    target_addr = current_base + mem.mem.disp
                    xor_val = instructions[i + 1].operands[1].imm & 0xFF
                    xor_ops.append((target_addr, xor_val))
                continue

            # Pattern 2: ldrb + eor (with immediate)
            if (
                insn.mnemonic == "ldrb"
                and i + 1 < len(instructions)
                and instructions[i + 1].mnemonic == "eor"
            ):
                eor_insn = instructions[i + 1]
                if len(eor_insn.operands) == 3 and eor_insn.operands[2].type == 2:
                    mem = insn.operands[1]
                    if mem.type == 3 and current_base is not None:
                        target_addr = current_base + mem.mem.disp
                        xor_val = eor_insn.operands[2].imm & 0xFF
                        xor_ops.append((target_addr, xor_val))
                continue

        if not xor_ops:
            return {}

        # Apply XOR operations
        extended = bytearray(self.data) + bytearray(0x10000)
        for addr, xor_val in xor_ops:
            off = self.vaddr_to_offset(addr)
            if off is not None and off < len(extended):
                extended[off] ^= xor_val

        # Extract decrypted strings
        addr_min = min(a for a, _ in xor_ops)
        addr_max = max(a for a, _ in xor_ops)
        off_start = self.vaddr_to_offset(addr_min)
        off_end = self.vaddr_to_offset(addr_max)

        if off_start is None or off_end is None:
            return {}

        off_end += 100

        strings = {}
        current = []
        str_start = off_start
        for j in range(off_start, min(off_end, len(extended))):
            b = extended[j]
            if b == 0:
                if len(current) >= 2:
                    s = bytes(current).decode("utf-8", errors="replace")
                    vaddr = addr_min + (str_start - off_start)
                    strings[vaddr] = s
                current = []
                str_start = j + 1
            elif 32 <= b < 127:
                current.append(b)
            else:
                current = []
                str_start = j + 1

        return strings

    @staticmethod
    def _split_into_tables(entries, max_gap=8):
        """Split a list of (offset, value) entries into sub-tables by gap size."""
        if not entries:
            return []
        tables = []
        current = [entries[0]]
        for i in range(1, len(entries)):
            gap = entries[i][0] - entries[i - 1][0]
            if gap > max_gap:
                tables.append(current)
                current = [entries[i]]
            else:
                current.append(entries[i])
        tables.append(current)
        return tables

    def find_hmac_keys(self, region: str = "EM") -> tuple:
        """Find HMAC access key and secret key using relocation table analysis.

        Returns (access_key, secret_key, all_decrypted_strings).
        """
        strings = self.decrypt_strings()
        if not strings:
            return None, None, strings

        hex32 = re.compile(r"^[0-9a-f]{32}$")
        alnum40 = re.compile(r"^[0-9a-z]{40}$")

        region_idx = REGION_INDICES.get(region, 3)
        target_idx = PROD_ENV_GROUP * REGIONS_PER_ENV + region_idx  # = 7

        # Collect relocations pointing to matching strings
        appid_entries = []
        secret_entries = []

        for reloc_off in sorted(self.relocs.keys()):
            target_vaddr = self.relocs[reloc_off]
            if target_vaddr in strings:
                s = strings[target_vaddr]
                if hex32.match(s):
                    appid_entries.append((reloc_off, s))
                elif alnum40.match(s):
                    secret_entries.append((reloc_off, s))

        # Split into sub-tables by detecting gaps > 8 bytes
        access_key = None
        appid_tables = self._split_into_tables(appid_entries)
        # The main AppId table is the largest one (should be 24 = 6 envs * 4 regions)
        if appid_tables:
            main_table = max(appid_tables, key=len)
            if target_idx < len(main_table):
                access_key = main_table[target_idx][1]

        secret_key = None
        secret_tables = self._split_into_tables(secret_entries)
        if secret_tables:
            # The secret table may be split into two halves (12 + 12) due to
            # non-40-char strings in between. Find the table containing the
            # target index, or use the largest table.
            main_table = max(secret_tables, key=len)
            if target_idx < len(main_table):
                secret_key = main_table[target_idx][1]
            else:
                # If the largest table is only 12 entries (half), the target
                # index 7 should still be within it (envs 0-2 = indices 0-11)
                for table in secret_tables:
                    if target_idx < len(table):
                        secret_key = table[target_idx][1]
                        break

        return access_key, secret_key, strings


# ============================================================================
# DEX Secret Extraction
# ============================================================================

def extract_dex_files(apk_path: str, output_dir: str) -> list:
    """Extract all DEX files from an APK."""
    dex_files = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if name.endswith(".dex"):
                z.extract(name, output_dir)
                dex_files.append(os.path.join(output_dir, name))
    return sorted(dex_files)


def extract_native_libs(apk_path: str, output_dir: str) -> list:
    """Extract ARM64 native libraries from an APK."""
    so_files = []
    with zipfile.ZipFile(apk_path, "r") as z:
        for name in z.namelist():
            if "arm64" in name and name.endswith(".so"):
                z.extract(name, output_dir)
                so_files.append(os.path.join(output_dir, name))
    return so_files


def find_rsa_public_key(dex_files: list) -> str | None:
    """Find the RSA public key for password encryption.

    Searches for base64-encoded PKCS#1 RSA public key (1024-bit, ~216 chars)
    starting with 'MIGfMA0GCSq' across all DEX files.
    """
    base64_chars = set(
        b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
    )
    prefix = b"MIGfMA0GCSq"

    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                data = f.read()

            idx = 0
            while True:
                idx = data.find(prefix, idx)
                if idx == -1:
                    break

                end = idx
                while end < len(data) and data[end] in base64_chars:
                    end += 1

                key = data[idx:end].decode("ascii")
                # RSA 1024-bit public key in base64 is ~216 chars
                if 200 <= len(key) <= 400:
                    return key
                idx = end
        except Exception:
            continue
    return None


def find_prod_secret(dex_files: list) -> str | None:
    """Find the prod secret for X-SIGNATURE HMAC computation.

    The prod secret is a 32-char lowercase hex string stored as a DEX string
    constant. We search for it with ULEB128 length prefix (0x20) and null
    terminator, then pick the most common candidate.
    """
    candidates = []
    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                data = f.read()

            pattern = re.compile(rb"\x20([0-9a-f]{32})\x00")
            for match in pattern.finditer(data):
                val = match.group(1).decode("ascii")
                candidates.append((os.path.basename(dex_path), val))
        except Exception:
            continue

    if not candidates:
        return None

    unique_vals = list(set(v for _, v in candidates))
    if len(unique_vals) == 1:
        return unique_vals[0]

    # Multiple candidates: prefer the one appearing in multiple DEX files
    val_counts = {}
    for _, v in candidates:
        val_counts[v] = val_counts.get(v, 0) + 1

    return max(val_counts, key=val_counts.get)


def find_vin_keys(dex_files: list) -> tuple:
    """Find the VIN encryption key and IV.

    These are 16-char lowercase hex strings used for AES-128-CBC encryption.
    The VIN key and IV are both stored in the same DEX file that contains
    'AES/CBC/PKCS5Padding'. We prefer a DEX file that has exactly 2 non-trivial
    16-char hex strings (the key and IV pair).
    """
    # Collect candidates per DEX file, only from files containing AES/CBC
    per_dex = {}  # dex_name -> list of 16-char hex values
    for dex_path in dex_files:
        try:
            with open(dex_path, "rb") as f:
                data = f.read()

            if b"AES/CBC/PKCS5Padding" not in data:
                continue

            pattern = re.compile(rb"\x10([0-9a-f]{16})\x00")
            vals = []
            seen = set()
            for match in pattern.finditer(data):
                val = match.group(1).decode("ascii")
                if val not in TRIVIAL_HEX16 and val not in seen:
                    seen.add(val)
                    vals.append(val)
            if vals:
                per_dex[os.path.basename(dex_path)] = vals
        except Exception:
            continue

    if not per_dex:
        return None, None

    # Prefer a DEX file that has exactly 2 candidates (key + IV pair)
    for dex_name, vals in sorted(per_dex.items()):
        if len(vals) == 2:
            return vals[0], vals[1]

    # Fallback: use the first DEX file with candidates
    for dex_name, vals in sorted(per_dex.items()):
        if len(vals) >= 2:
            return vals[0], vals[1]
        elif len(vals) == 1:
            # Check other DEX files for the second value
            for other_name, other_vals in sorted(per_dex.items()):
                if other_name != dex_name:
                    for v in other_vals:
                        if v != vals[0]:
                            return vals[0], v
            return vals[0], None

    return None, None


# ============================================================================
# Main Extraction Pipeline
# ============================================================================

def extract_secrets(base_apk: str, arm64_apk: str = None, region: str = "EM"):
    """Extract all 6 secrets from the Zeekr APK files."""
    secrets = {
        "hmac_access_key": None,
        "hmac_secret_key": None,
        "password_public_key": None,
        "prod_secret": None,
        "vin_key": None,
        "vin_iv": None,
    }

    with tempfile.TemporaryDirectory() as tmpdir:
        print(f"\n{'=' * 60}")
        print(f"  Zeekr APK Secret Extractor")
        print(f"  Target region: {region}")
        print(f"{'=' * 60}\n")

        # Step 1: Extract DEX files
        print("[1/4] Extracting DEX files from base APK...")
        dex_files = extract_dex_files(base_apk, tmpdir)
        print(f"      Found {len(dex_files)} DEX files")

        # Step 2: Extract native libraries
        print("[2/4] Extracting native libraries...")
        so_files = []
        if arm64_apk:
            so_files = extract_native_libs(arm64_apk, tmpdir)
        if not so_files:
            so_files = extract_native_libs(base_apk, tmpdir)
        print(f"      Found {len(so_files)} native libraries")

        # Step 3: Extract Java-level secrets from DEX files
        print("[3/4] Searching DEX files for secrets...")

        print("      Looking for RSA password public key...")
        key = find_rsa_public_key(dex_files)
        if key:
            secrets["password_public_key"] = key
            print(f"      [OK] Password Public Key ({len(key)} chars)")
        else:
            print("      [!!] Password Public Key: NOT FOUND")

        print("      Looking for prod secret...")
        prod = find_prod_secret(dex_files)
        if prod:
            secrets["prod_secret"] = prod
            print(f"      [OK] Prod Secret: {prod}")
        else:
            print("      [!!] Prod Secret: NOT FOUND")

        print("      Looking for VIN encryption key and IV...")
        vin_key, vin_iv = find_vin_keys(dex_files)
        if vin_key and vin_iv:
            secrets["vin_key"] = vin_key
            secrets["vin_iv"] = vin_iv
            print(f"      [OK] VIN Key: {vin_key}")
            print(f"      [OK] VIN IV:  {vin_iv}")
        else:
            print("      [!!] VIN Key/IV: NOT FOUND")

        # Step 4: Extract HMAC keys from native library
        print("[4/4] Decrypting native library secrets (OLLVM deobfuscation)...")

        libenv_path = None
        for so_path in so_files:
            if "libenv.so" in so_path:
                libenv_path = so_path
                break

        if libenv_path is None:
            print("      [!!] libenv.so not found!")
            print("      Make sure to provide the ARM64 split APK")
        else:
            print("      Disassembling and decrypting libenv.so...")
            analyzer = NativeLibAnalyzer(libenv_path)
            access_key, secret_key, all_strings = analyzer.find_hmac_keys(region)

            if access_key:
                secrets["hmac_access_key"] = access_key
                print(f"      [OK] HMAC Access Key: {access_key}")
            else:
                print("      [!!] HMAC Access Key: NOT FOUND")
                hex32 = re.compile(r"^[0-9a-f]{32}$")
                candidates = [
                    (a, s) for a, s in sorted(all_strings.items()) if hex32.match(s)
                ]
                if candidates:
                    print(f"      {len(candidates)} potential candidates found:")
                    for addr, val in candidates:
                        print(f"        0x{addr:x}: {val}")

            if secret_key:
                secrets["hmac_secret_key"] = secret_key
                print(f"      [OK] HMAC Secret Key: {secret_key}")
            else:
                print("      [!!] HMAC Secret Key: NOT FOUND")
                alnum40 = re.compile(r"^[0-9a-z]{40}$")
                candidates = [
                    (a, s) for a, s in sorted(all_strings.items()) if alnum40.match(s)
                ]
                if candidates:
                    print(f"      {len(candidates)} potential candidates found:")
                    for addr, val in candidates:
                        print(f"        0x{addr:x}: {val}")

    # Print summary
    print(f"\n{'=' * 60}")
    print(f"  RESULTS")
    print(f"{'=' * 60}\n")

    all_found = True
    for key, value in secrets.items():
        status = "[OK]" if value else "[MISSING]"
        if value:
            display = value if len(value) <= 60 else f"{value[:40]}...{value[-20:]}"
        else:
            display = "NOT FOUND"
            all_found = False
        print(f"  {status} {key}: {display}")

    if all_found:
        print(f"\n  All 6 secrets extracted successfully!")
    else:
        print(f"\n  Some secrets could not be extracted automatically.")
        print(f"  You may need to use JADX for manual inspection.")

    # Save to JSON
    output_path = os.path.join(
        os.path.dirname(os.path.abspath(base_apk)), "zeekr_secrets.json"
    )
    with open(output_path, "w") as f:
        json.dump(secrets, f, indent=2)
    print(f"\n  Secrets saved to: {output_path}")

    return secrets


def main():
    parser = argparse.ArgumentParser(
        description="Extract secrets from Zeekr APK for Home Assistant integration",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s zeekr_base.apk zeekr_arm64.apk
  %(prog)s zeekr_base.apk zeekr_arm64.apk --region EU
  %(prog)s zeekr_base.apk  # Will try to find .so files in base APK

To pull APKs from a connected Android device:
  adb shell pm path com.zeekr.global
  adb pull <base_path> zeekr_base.apk
  adb pull <arm64_path> zeekr_arm64.apk
        """,
    )
    parser.add_argument("base_apk", help="Path to the main Zeekr APK (base.apk)")
    parser.add_argument(
        "arm64_apk", nargs="?", help="Path to the ARM64 split APK (optional)"
    )
    parser.add_argument(
        "--region",
        default="EM",
        choices=["CN", "SEA", "EU", "EM"],
        help="Target region (default: EM)",
    )

    args = parser.parse_args()

    if not os.path.exists(args.base_apk):
        print(f"ERROR: File not found: {args.base_apk}")
        sys.exit(1)

    if args.arm64_apk and not os.path.exists(args.arm64_apk):
        print(f"ERROR: File not found: {args.arm64_apk}")
        sys.exit(1)

    extract_secrets(args.base_apk, args.arm64_apk, args.region)


if __name__ == "__main__":
    main()
