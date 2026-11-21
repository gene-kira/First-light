"""
STEGO-VAULT PRO — Secure Studio Edition (v2.5)
Windows-friendly encrypted payload vault with PNG LSB cards, QR transfer,
local Security Lab (with Parallax Swarm forecasting, ChronoMind time checks,
Water-Data flow modeling, and Altered States session modes), vault card
auditing (APEX-Sentinel / VANTABLACK Guardian Core), and an optional
Browser Bridge (localhost API + MV3 extension generator).

Security notes:
- The master passphrase is never saved in plaintext.
- Webcam face detection is NOT used as authentication.
- Administrator privileges are optional; data is stored under the user's
  writable application-data directory.
- PNG cards are lossless containers. Do not resize/recompress them.
- When enabled, the Browser Bridge binds strictly to 127.0.0.1 and requires a
  per-session bearer token generated locally by Stego-Vault Pro.
"""

import os
import re
import csv
import sys
import json
import math
import time
import base64
import secrets
import string
import struct
import logging
import threading
import subprocess
import ctypes
import platform
import datetime
from pathlib import Path
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---- Dependency bootstrap (user-level; no admin required) -----------------
def ensure_package(import_name, package_name):
    try:
        __import__(import_name)
        return True
    except ImportError:
        if getattr(sys, "frozen", False):
            messagebox.showerror(
                "Missing dependency",
                f"Required package '{package_name}' is not bundled in this build."
            )
            return False
        try:
            subprocess.check_call([
                sys.executable, "-m", "pip", "install", "--user", package_name
            ])
            __import__(import_name)
            return True
        except Exception as exc:
            messagebox.showerror(
                "Missing dependency",
                f"Could not install {package_name}.\n\n"
                f"Run:\n{sys.executable} -m pip install --user {package_name}\n\n"
                f"Details: {exc}"
            )
            return False

# Tkinter is part of the normal Windows Python installation.
if not ensure_package("PIL", "Pillow"):
    raise SystemExit(1)
if not ensure_package("cryptography", "cryptography"):
    raise SystemExit(1)
if not ensure_package("qrcode", "qrcode"):
    raise SystemExit(1)

from PIL import Image, ImageDraw, ImageTk
from cryptography.fernet import Fernet, InvalidToken
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode

try:
    import cv2
except ImportError:
    cv2 = None

APP_NAME = "StegoVaultPro"
APP_VERSION = "2.5"
MAGIC = b"SVP2"
SALT_SIZE = 16
KDF_ITERATIONS = 600_000
HEADER = MAGIC + struct.pack(">I", 0)  # replaced with actual encrypted length
DEFAULT_CARD_SIZE = (1200, 800)
MAX_IMPORT_BYTES = 20 * 1024 * 1024
SYMBOL_SET = "!@#$%^&*()-_=+[]{}:,.?"
AMBIGUOUS_CHARS = set("0O1lI|")
WORD_POOL = (
    "amber", "anchor", "atlas", "beacon", "breeze", "canyon", "cedar", "cipher",
    "cobalt", "comet", "compass", "coral", "crest", "delta", "ember", "falcon",
    "fjord", "flint", "forest", "glacier", "harbor", "horizon", "island", "jade",
    "kernel", "lantern", "latitude", "legend", "meadow", "meridian", "monolith",
    "nebula", "oasis", "orbit", "pebble", "phoenix", "prism", "quartz", "raven",
    "ridge", "river", "summit", "tempest", "timber", "vector", "velvet", "zenith"
)
BRIDGE_HOST = "127.0.0.1"
BRIDGE_PORT = 47831

# Altered States session & cognitive-pacing profiles (transparent local presets)
ALTERED_STATES_MODES = {
    "Baseline Focus": {
        "description": "Balanced default state: standard 24-char secrets, 20s clipboard auto-clear, and calm slate/blue contrast.",
        "bg": "#0b1220",
        "panel": "#111c2e",
        "panel2": "#17243a",
        "accent": "#60a5fa",
        "password_len": 24,
        "phrase_words": 4,
        "clipboard_sec": 20,
    },
    "Flow / Deep Work": {
        "description": "Uninterrupted deep-work state: longer 32-char secrets, 5-word passphrases, and 45s clipboard buffer.",
        "bg": "#071318",
        "panel": "#0d1f26",
        "panel2": "#132c36",
        "accent": "#2dd4bf",
        "password_len": 32,
        "phrase_words": 5,
        "clipboard_sec": 45,
    },
    "Hypnagogic / Night Low-Glare": {
        "description": "Low-eyestrain twilight state: deep obsidian/umber tones, 20-char secrets, and quick 12s clipboard clear.",
        "bg": "#09080f",
        "panel": "#12101c",
        "panel2": "#1c192b",
        "accent": "#c084fc",
        "password_len": 20,
        "phrase_words": 4,
        "clipboard_sec": 12,
    },
    "Lucid / High-Contrast": {
        "description": "Crisp high-alert state: VANTABLACK ground with sharp amber/gold signifiers and 28-char secrets.",
        "bg": "#040507",
        "panel": "#0c0f14",
        "panel2": "#161b24",
        "accent": "#fbbf24",
        "password_len": 28,
        "phrase_words": 6,
        "clipboard_sec": 15,
    },
}

def app_data_dir():
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    path = Path(base) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path

DATA_DIR = app_data_dir()
LOG_PATH = DATA_DIR / "vault_audit.log"
SETTINGS_PATH = DATA_DIR / "settings.json"
EXTENSION_DIR = DATA_DIR / "browser_extension_mv3"

logging.basicConfig(
    filename=str(LOG_PATH),
    level=logging.INFO,
    format="%(asctime)s | %(levelname)s | %(message)s",
    encoding="utf-8"
)
log = logging.getLogger(APP_NAME)

def is_admin():
    if os.name != "nt":
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False

def load_settings():
    if not SETTINGS_PATH.is_file():
        return {}
    try:
        data = json.loads(SETTINGS_PATH.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}

def save_settings(settings_dict):
    try:
        SETTINGS_PATH.write_text(
            json.dumps(settings_dict, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
    except Exception as exc:
        log.warning("Could not save settings: %s", exc)

def check_time_integrity():
    """ChronoMind Nexus: verify local clock sanity, UTC offset, and monotonic tick."""
    now_local = datetime.datetime.now().astimezone()
    now_utc = datetime.datetime.now(datetime.timezone.utc)
    offset = now_local.utcoffset() or datetime.timedelta(0)
    offset_hours = offset.total_seconds() / 3600.0
    mono_t1 = time.monotonic()
    mono_t2 = time.monotonic()
    year_sane = 2020 <= now_utc.year <= 2100
    status = "Nominal / Synchronized" if year_sane else "Check System Clock Year"
    return {
        "status": status,
        "local_iso": now_local.isoformat(timespec="seconds"),
        "utc_iso": now_utc.isoformat(timespec="seconds"),
        "utc_offset_hours": round(offset_hours, 2),
        "monotonic_ok": mono_t2 >= mono_t1,
    }

def secure_key(passphrase, salt):
    if not passphrase or len(passphrase) < 10:
        raise ValueError("Use a master passphrase of at least 10 characters.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS
    )
    return base64.urlsafe_b64encode(kdf.derive(passphrase.encode("utf-8")))

def _build_alphabet(symbols=True, exclude_ambiguous=False, custom_symbols=None):
    sym_chars = custom_symbols if custom_symbols else SYMBOL_SET
    lower = "".join(c for c in string.ascii_lowercase if not (exclude_ambiguous and c in AMBIGUOUS_CHARS))
    upper = "".join(c for c in string.ascii_uppercase if not (exclude_ambiguous and c in AMBIGUOUS_CHARS))
    digits = "".join(c for c in string.digits if not (exclude_ambiguous and c in AMBIGUOUS_CHARS))
    syms = "".join(c for c in sym_chars if not (exclude_ambiguous and c in AMBIGUOUS_CHARS))
    if not (lower or upper or digits or syms):
        raise ValueError("Character set is empty after filtering.")
    return lower, upper, digits, syms

def secure_random_password(length, symbols=True, exclude_ambiguous=False, custom_symbols=None):
    lower, upper, digits, syms = _build_alphabet(
        symbols=symbols,
        exclude_ambiguous=exclude_ambiguous,
        custom_symbols=custom_symbols
    )
    alphabet = lower + upper + digits + (syms if symbols else "")
    if length < 8 or length > 256:
        raise ValueError("Password length must be between 8 and 256.")
    required = []
    if lower:
        required.append(secrets.choice(lower))
    if upper:
        required.append(secrets.choice(upper))
    if digits:
        required.append(secrets.choice(digits))
    if symbols and syms:
        required.append(secrets.choice(syms))
    required.extend(secrets.choice(alphabet) for _ in range(max(0, length - len(required))))
    secrets.SystemRandom().shuffle(required)
    return "".join(required[:length])

def generate_passphrase_words(word_count=4, separator="-", capitalize=True, add_number=True):
    word_count = max(2, min(12, int(word_count)))
    chosen = [secrets.choice(WORD_POOL) for _ in range(word_count)]
    if capitalize:
        chosen = [w.capitalize() for w in chosen]
    phrase = (separator or "-").join(chosen)
    if add_number:
        phrase = f"{phrase}{separator or '-'}{secrets.randbelow(90) + 10}"
    return phrase


# Approximate letter-to-letter transliteration maps for mixed-script passwords.
# These are Unicode characters, not translations of whole words.
MULTI_SCRIPT_MAPS = {
    "Greek": {
        "a": "α", "b": "β", "c": "κ", "d": "δ", "e": "ε", "f": "φ", "g": "γ", "h": "η",
        "i": "ι", "j": "ξ", "k": "κ", "l": "λ", "m": "μ", "n": "ν", "o": "ο", "p": "ρ",
        "q": "θ", "r": "ρ", "s": "σ", "t": "τ", "u": "υ", "v": "ν", "w": "ω", "x": "χ",
        "y": "ψ", "z": "ζ"
    },
    "Cyrillic": {
        "a": "а", "b": "б", "c": "с", "d": "д", "e": "е", "f": "ф", "g": "г", "h": "н",
        "i": "і", "j": "ј", "k": "к", "l": "л", "m": "м", "n": "п", "o": "о", "p": "р",
        "q": "я", "r": "г", "s": "ѕ", "t": "т", "u": "ц", "v": "в", "w": "ш", "x": "х",
        "y": "у", "z": "з"
    },
    "Armenian": {
        "a": "ա", "b": "բ", "c": "ց", "d": "դ", "e": "ե", "f": "ֆ", "g": "գ", "h": "հ",
        "i": "ի", "j": "ջ", "k": "կ", "l": "լ", "m": "մ", "n": "ն", "o": "ո", "p": "պ",
        "q": "ք", "r": "ր", "s": "ս", "t": "տ", "u": "ու", "v": "վ", "w": "ւ", "x": "խ",
        "y": "յ", "z": "զ"
    },
    "Ukrainian": {
        "a": "а", "b": "б", "c": "ц", "d": "д", "e": "е", "f": "ф", "g": "ґ", "h": "г",
        "i": "і", "j": "й", "k": "к", "l": "л", "m": "м", "n": "н", "o": "о", "p": "п",
        "q": "к", "r": "р", "s": "с", "t": "т", "u": "у", "v": "в", "w": "ш", "x": "х",
        "y": "и", "z": "з"
    }
}

KEYBOARD_SEQUENCES = (
    "qwertyuiop",
    "asdfghjkl",
    "zxcvbnm",
    "0123456789",
    "abcdefghijklmnopqrstuvwxyz"
)

def detect_system_language():
    """Return a display label for the OS locale; generator remains ASCII by default."""
    try:
        import locale
        lang = (locale.getlocale()[0] or "").lower()
        if lang.startswith(("el",)):
            return "Greek"
        if lang.startswith(("ru", "bg", "sr")):
            return "Cyrillic"
        if lang.startswith(("hy",)):
            return "Armenian"
        if lang.startswith(("uk",)):
            return "Ukrainian"
    except Exception:
        pass
    return "English / Standard"

def apply_mixed_scripts(password):
    """Represent each alphabetic character using a randomly selected script."""
    output = []
    previous_script = None
    script_names = list(MULTI_SCRIPT_MAPS)
    for char in password:
        lower = char.lower()
        if lower not in string.ascii_lowercase:
            output.append(char)
            continue
        choices = [name for name in script_names if name != previous_script]
        script_name = secrets.choice(choices or script_names)
        mapped = MULTI_SCRIPT_MAPS[script_name][lower]
        output.append(mapped.upper() if char.isupper() else mapped)
        previous_script = script_name
    return "".join(output)

def make_masked_preview(password, visible_count, mask_char="•"):
    """Show the first N Unicode characters and mask the remainder."""
    visible_count = max(0, min(int(visible_count), len(password)))
    return password[:visible_count] + mask_char * (len(password) - visible_count)

def _stylize_word(word):
    """Apply subtle capitalization/substitution while keeping readability."""
    cleaned = re.sub(r"[^A-Za-z0-9]", "", word)
    if not cleaned:
        return ""
    leet = {"a": "@", "e": "3", "i": "1", "o": "0", "s": "$"}
    chars = []
    for idx, ch in enumerate(cleaned.lower()):
        if idx == 0:
            chars.append(ch.upper())
        elif ch in leet and secrets.randbelow(3) == 0:
            chars.append(leet[ch])
        elif secrets.randbelow(4) == 0:
            chars.append(ch.upper())
        else:
            chars.append(ch)
    return "".join(chars)

def generate_adaptive_password(length, symbols=True, base_words="",
                               use_mixed_scripts=False, padding_mode="balanced",
                               exclude_ambiguous=False, custom_symbols=None):
    """Generate an adaptive password combining optional base words and cryptographic padding."""
    if length < 8 or length > 256:
        raise ValueError("Password length must be between 8 and 256.")

    lower, upper, digits, syms = _build_alphabet(
        symbols=symbols,
        exclude_ambiguous=exclude_ambiguous,
        custom_symbols=custom_symbols
    )
    raw_words = [w.strip() for w in re.split(r"[,;\s]+", base_words or "") if w.strip()]
    stylized_words = [_stylize_word(w) for w in raw_words]
    stylized_words = [w for w in stylized_words if w]

    pad_alphabet = lower + upper + digits + (syms if symbols else "")
    sep_pool = syms if (symbols and syms) else "-_."
    separator = secrets.choice(sep_pool)

    pad_ratios = {"minimal": 0.25, "balanced": 0.55, "heavy": 0.85}
    ratio = pad_ratios.get(padding_mode, 0.55)

    if not stylized_words:
        pwd = secure_random_password(
            length,
            symbols=symbols,
            exclude_ambiguous=exclude_ambiguous,
            custom_symbols=custom_symbols
        )
    else:
        pieces = []
        for idx, word in enumerate(stylized_words):
            pieces.append(word)
            if idx < len(stylized_words) - 1:
                pieces.append(separator)

        joined = "".join(pieces)
        target_pad_len = max(4, int(length * ratio)) if len(joined) < length else 2
        pad_chars = [secrets.choice(pad_alphabet) for _ in range(target_pad_len)]
        if symbols and syms and not any(c in syms for c in joined + "".join(pad_chars)):
            pad_chars[0] = secrets.choice(syms)
        if digits and not any(c.isdigit() for c in joined + "".join(pad_chars)):
            pad_chars[-1] = secrets.choice(digits)

        if padding_mode == "minimal":
            combined = joined + separator + "".join(pad_chars)
        elif padding_mode == "heavy":
            half = len(pad_chars) // 2
            combined = "".join(pad_chars[:half]) + separator + joined + separator + "".join(pad_chars[half:])
        else:
            combined = joined + separator + "".join(pad_chars)

        while len(combined) < length:
            combined += secrets.choice(pad_alphabet)
        pwd = combined[:length]

    if use_mixed_scripts:
        pwd = apply_mixed_scripts(pwd)
    return pwd

def _format_duration(seconds):
    if seconds < 1:
        return "< 1 second"
    if seconds < 60:
        return f"{seconds:.1f} seconds"
    minutes = seconds / 60
    if minutes < 60:
        return f"{minutes:.1f} minutes"
    hours = minutes / 60
    if hours < 24:
        return f"{hours:.1f} hours"
    days = hours / 24
    if days < 365.25:
        return f"{days:.1f} days"
    years = days / 365.25
    if years < 1e6:
        return f"{years:,.1f} years"
    if years < 1e9:
        return f"{years / 1e6:,.2f} million years"
    return f"{years / 1e9:,.2f} billion years"

def parallax_swarm_forecast(length, unique_chars, pool_size, raw_entropy, penalty_pct, repetition_pct, longest_run):
    """
    Parallax Swarm Engine: multi-perspective ensemble scoring & 'best guess' consensus.
    Combines three complementary perspectives:
1. Sentinel-Strict (penalizes any pattern, run, or low uniqueness aggressively)
2. Entropy-Structural (scales information-theoretic entropy against a 110-bit target)
3. Length-Resilient (rewards length + diversity while accounting for repetition)
    """
    if length <= 0:
        return {
            "consensus_score": 0,
            "spread": 0,
            "confidence": "None",
            "swarm_notes": ["No input provided to swarm estimators."],
            "best_guess": "Generate or enter at least 12–16 varied characters."
        }
    multiplier = max(0.35, 1.0 - penalty_pct / 100.0)
    effective_entropy = max(0.0, raw_entropy * multiplier)

    s_structural = int(max(0, min(100, round((effective_entropy / 110.0) * 100.0))))
    strict_drag = penalty_pct * 1.15 + max(0.0, repetition_pct - 25.0) * 0.5 + max(0, longest_run - 2) * 6.0
    s_strict = int(max(0, min(100, round((raw_entropy / 110.0) * 100.0 - strict_drag))))
    diversity_ratio = unique_chars / max(1, length)
    s_resilient = int(max(0, min(100, round(
        min(65.0, length * 2.8) + diversity_ratio * 25.0 + min(15.0, math.log2(max(2, pool_size)) * 2.2) - penalty_pct * 0.6
    ))))

    if length < 10:
        s_structural = min(s_structural, 45)
        s_strict = min(s_strict, 40)
        s_resilient = min(s_resilient, 50)
    if length < 8:
        s_structural = min(s_structural, 25)
        s_strict = min(s_strict, 20)
        s_resilient = min(s_resilient, 30)

    members = [s_structural, s_strict, s_resilient]
    consensus = int(round(sum(members) / len(members)))
    spread = max(members) - min(members)
    confidence = "High Consensus" if spread <= 10 else ("Moderate Spread" if spread <= 22 else "Divergent Signals")

    if penalty_pct > 0 or repetition_pct >= 35.0:
        best_guess = "Eliminate repeated runs/substrings first—removing penalties yields faster gains than raw length alone."
    elif length < 16:
        best_guess = f"Extend from {length} to 18+ characters to widen the safety margin against offline guessing."
    else:
        best_guess = "Strong multi-perspective alignment; store in an encrypted vault and avoid reuse."

    return {
        "consensus_score": consensus,
        "spread": spread,
        "confidence": confidence,
        "swarm_notes": [
            f"Structural perspective: {s_structural}/100 ({effective_entropy:.1f} eff. bits)",
            f"Sentinel-Strict perspective: {s_strict}/100 (drag {strict_drag:.1f})",
            f"Length-Resilient perspective: {s_resilient}/100 (uniqueness {diversity_ratio * 100:.0f}%)",
        ],
        "best_guess": best_guess,
    }

def simulate_water_data_flow(estimated_bytes, capacity_bytes, flow_rate_kbps=64.0):
    """
    Intelligent Water-Data Physics Engine:
    Models payload volume inside the PNG LSB reservoir and laminar/turbulent bit-stream transfer.
    """
    cap = max(1, int(capacity_bytes))
    vol = max(0, int(estimated_bytes))
    headroom = cap - vol
    fill_ratio = vol / cap
    fill_pct = round(fill_ratio * 100.0, 2)

    if fill_ratio > 1.0:
        regime = "Overflow / Spillover"
    elif fill_ratio >= 0.85:
        regime = "High-Head / Near-Crest"
    elif fill_ratio >= 0.40:
        regime = "Laminar Reservoir"
    else:
        regime = "Low-Load / Calm Basin"

    # Simulated transfer time at flow_rate_kbps (1 KB = 1024 B)
    rate_bps = max(1.0, float(flow_rate_kbps) * 1024.0)
    eta_seconds = vol / rate_bps
    return {
        "volume_bytes": vol,
        "capacity_bytes": cap,
        "headroom_bytes": headroom,
        "fill_pct": fill_pct,
        "regime": regime,
        "eta_seconds": round(eta_seconds, 2),
    }

def analyze_password(password):
    """Perform local strength estimation, pattern detection, repetition analysis, and predictive modeling."""
    if not password:
        return {
            "score": 0,
            "rating": "Empty",
            "entropy_bits": 0.0,
            "raw_entropy_bits": 0.0,
            "pool_size": 0,
            "length": 0,
            "unique_chars": 0,
            "repetition_pct": 0.0,
            "longest_run": 0,
            "patterns": ["No password provided."],
            "recommendations": ["Enter or generate a password with at least 12–16 characters."],
            "reasoning_steps": [
                "Step 1 (Input): No characters provided -> 0 entropy bits and score 0/100."
            ],
            "predictions": {
                "online_throttled": "Instant (no secret)",
                "offline_fast_gpu": "Instant (no secret)",
                "if_plus_4_chars": "Add 12+ characters to reach a strong baseline."
            },
            "swarm": parallax_swarm_forecast(0, 0, 0, 0.0, 0.0, 0.0, 0),
        }

    length = len(password)
    unique_chars = len(set(password))
    repetition_pct = round(((length - unique_chars) / length) * 100.0, 1)

    longest_run = 1
    current_run = 1
    for i in range(1, length):
        if password[i] == password[i - 1]:
            current_run += 1
            longest_run = max(longest_run, current_run)
        else:
            current_run = 1

    has_lower = any(c.islower() for c in password)
    has_upper = any(c.isupper() for c in password)
    has_digit = any(c.isdigit() for c in password)
    has_ascii_sym = any(c in SYMBOL_SET for c in password)
    has_non_ascii = any(ord(c) > 127 for c in password)

    pool_parts = []
    pool_size = 0
    if has_lower:
        pool_size += 26
        pool_parts.append("lowercase(26)")
    if has_upper:
        pool_size += 26
        pool_parts.append("uppercase(26)")
    if has_digit:
        pool_size += 10
        pool_parts.append("digits(10)")
    if has_ascii_sym:
        pool_size += len(SYMBOL_SET)
        pool_parts.append(f"symbols({len(SYMBOL_SET)})")
    if has_non_ascii:
        pool_size += 64
        pool_parts.append("unicode(+64)")

    pool_size = max(pool_size, unique_chars, 1)
    raw_entropy = length * math.log2(pool_size)

    patterns = []
    penalty = 0.0

    if longest_run >= 3:
        p_val = min(18.0, (longest_run - 2) * 5.0)
        patterns.append(f"Repeated character run detected (up to {longest_run}x in a row; -{p_val:.0f}% penalty).")
        penalty += p_val

    if repetition_pct >= 35.0:
        p_val = min(20.0, (repetition_pct - 30.0) * 0.6)
        patterns.append(f"High character repetition ({repetition_pct}% of characters repeat; -{p_val:.0f}% penalty).")
        penalty += p_val

    lower_pwd = password.lower()
    seq_hit = False
    for seq in KEYBOARD_SEQUENCES:
        rev = seq[::-1]
        for idx in range(len(seq) - 3):
            chunk = seq[idx:idx + 4]
            rev_chunk = rev[idx:idx + 4]
            if chunk in lower_pwd or rev_chunk in lower_pwd:
                seq_hit = True
                break
        if seq_hit:
            break
    if seq_hit:
        patterns.append("Sequential or keyboard-walk pattern detected (4+ consecutive chars; -15% penalty).")
        penalty += 15.0

    repeated_subs = set()
    for size in range(3, min(8, length // 2 + 1)):
        for start in range(length - size + 1):
            sub = password[start:start + size]
            if password.count(sub) > 1:
                repeated_subs.add(sub)
    if repeated_subs:
        p_val = min(15.0, len(repeated_subs) * 5.0)
        sample = ", ".join(sorted(repeated_subs)[:3])
        patterns.append(f"Repeated substring pattern ({sample}; -{p_val:.0f}% penalty).")
        penalty += p_val

    if re.search(r"(19\d\d|20\d\d|1234|admin|password|qwerty|letmein|welcome)", lower_pwd):
        patterns.append("Common word, year, or predictable token detected (-15% penalty).")
        penalty += 15.0

    if has_non_ascii:
        patterns.append("Non-ASCII / mixed-script Unicode characters present.")

    if not patterns:
        patterns.append("No obvious sequential, dictionary, or heavy repetition patterns found.")

    multiplier = max(0.35, 1.0 - penalty / 100.0)
    effective_entropy = max(0.0, raw_entropy * multiplier)

    score = int(max(0, min(100, round((effective_entropy / 110.0) * 100.0))))
    if length < 10:
        score = min(score, 45)
    if length < 8:
        score = min(score, 25)

    if score >= 85:
        rating = "Very Strong"
    elif score >= 68:
        rating = "Strong"
    elif score >= 48:
        rating = "Good"
    elif score >= 28:
        rating = "Fair"
    else:
        rating = "Weak"

    expected_guesses = 0.5 * (2.0 ** min(effective_entropy, 256.0))
    online_sec = expected_guesses / 10.0
    gpu_sec = expected_guesses / 1e10

    projected_entropy = min(256.0, effective_entropy + 4.0 * math.log2(pool_size))
    projected_score = int(max(0, min(100, round((projected_entropy / 110.0) * 100.0))))

    swarm = parallax_swarm_forecast(
        length=length,
        unique_chars=unique_chars,
        pool_size=pool_size,
        raw_entropy=raw_entropy,
        penalty_pct=penalty,
        repetition_pct=repetition_pct,
        longest_run=longest_run,
    )

    reasoning_steps = [
        f"1. Alphabet & Length: {length} chars across [{', '.join(pool_parts) or 'custom'}] -> estimated pool ~{pool_size}, raw entropy {raw_entropy:.1f} bits.",
        f"2. Pattern & Repetition Audit: repetition {repetition_pct}%, max run {longest_run} -> total penalty {penalty:.0f}% (retention factor {multiplier:.2f}x).",
        f"3. Effective Strength & Forecast: {effective_entropy:.1f} effective bits -> score {score}/100 ({rating}). Adding +4 chars at this pool would project ~{projected_entropy:.1f} bits (score ~{projected_score}/100)."
    ]

    recommendations = []
    if length < 16:
        recommendations.append("Increase length to at least 16 characters for stronger resistance.")
    if not (has_lower and has_upper and has_digit):
        recommendations.append("Combine lowercase letters, uppercase letters, and digits.")
    if not has_ascii_sym and not has_non_ascii:
        recommendations.append("Add symbols to expand the character space.")
    if longest_run >= 3 or repetition_pct >= 35.0:
        recommendations.append("Reduce repeated characters or increase random padding.")
    if seq_hit:
        recommendations.append("Replace keyboard walks or alphabetical/numeric runs with random characters.")
    if has_non_ascii:
        recommendations.append("Verify target login forms support Unicode/non-ASCII input before relying on it.")
    if not recommendations:
        recommendations.append("Password looks solid. Store it in an encrypted vault rather than plain text.")

    return {
        "score": score,
        "rating": rating,
        "entropy_bits": round(effective_entropy, 1),
        "raw_entropy_bits": round(raw_entropy, 1),
        "pool_size": pool_size,
        "length": length,
        "unique_chars": unique_chars,
        "repetition_pct": repetition_pct,
        "longest_run": longest_run,
        "patterns": patterns,
        "recommendations": recommendations,
        "reasoning_steps": reasoning_steps,
        "predictions": {
            "online_throttled": _format_duration(online_sec),
            "offline_fast_gpu": _format_duration(gpu_sec),
            "if_plus_4_chars": f"~{projected_entropy:.1f} bits (score ~{projected_score}/100)"
        },
        "swarm": swarm,
    }

def estimate_card_capacity(text, attachment_paths, card_size=DEFAULT_CARD_SIZE):
    """Predict approximate encrypted byte size and LSB PNG card utilization."""
    width, height = card_size
    capacity_bytes = (width * height) // 8
    attachments_raw_bytes = 0
    for path in attachment_paths:
        try:
            attachments_raw_bytes += Path(path).stat().st_size
        except OSError:
            pass
    est_b64_bytes = int(math.ceil(attachments_raw_bytes / 3.0) * 4)
    est_text_bytes = len((text or "").encode("utf-8"))
    est_total_bytes = 8 + SALT_SIZE + 120 + est_text_bytes + est_b64_bytes
    pct_used = round((est_total_bytes / max(1, capacity_bytes)) * 100.0, 1)
    flow = simulate_water_data_flow(est_total_bytes, capacity_bytes)
    return {
        "capacity_bytes": capacity_bytes,
        "estimated_bytes": est_total_bytes,
        "pct_used": pct_used,
        "fits": est_total_bytes <= capacity_bytes,
        "flow": flow,
    }

def audit_vault_card(image_path):
    """APEX-Sentinel & VANTABLACK Guardian Core: non-destructive LSB card header & capacity audit."""
    p = Path(image_path)
    if not p.is_file():
        raise ValueError("Selected image file does not exist.")
    file_size = p.stat().st_size
    with Image.open(p) as source:
        fmt = source.format or "Unknown"
        mode = source.mode
        width, height = source.size
        capacity_bytes = (width * height) // 8
        rgb = source.convert("RGB")
        pixels = rgb.load()
        header_bits = []
        for y in range(height):
            for x in range(width):
                header_bits.append(str(pixels[x, y][0] & 1))
                if len(header_bits) == 64:
                    break
            if len(header_bits) == 64:
                break
        header = bits_to_bytes("".join(header_bits))
        has_magic = len(header) >= 4 and header[:4] == MAGIC
        payload_len = struct.unpack(">I", header[4:8])[0] if has_magic else 0
        valid_len = has_magic and (0 < payload_len <= max(0, capacity_bytes - 8))
        flow = simulate_water_data_flow(8 + payload_len if valid_len else 0, capacity_bytes)
        return {
            "file_name": p.name,
            "file_bytes": file_size,
            "format": fmt,
            "mode": mode,
            "dimensions": f"{width}x{height}",
            "capacity_bytes": capacity_bytes,
            "has_svp2_magic": has_magic,
            "payload_len": payload_len if has_magic else 0,
            "header_valid": valid_len,
            "flow": flow,
        }

def encode_package(payload, passphrase):
    salt = secrets.token_bytes(SALT_SIZE)
    token = Fernet(secure_key(passphrase, salt)).encrypt(
        json.dumps(payload, ensure_ascii=False).encode("utf-8")
    )
    encrypted = salt + token
    return MAGIC + struct.pack(">I", len(encrypted)) + encrypted

def decode_package(package, passphrase):
    if len(package) < 8 + SALT_SIZE + 32:
        raise ValueError("The selected file does not contain a complete vault payload.")
    if package[:4] != MAGIC:
        raise ValueError("Unsupported or damaged vault-card format.")
    payload_len = struct.unpack(">I", package[4:8])[0]
    if payload_len <= 0 or payload_len > len(package) - 8:
        raise ValueError("Invalid payload length in vault card.")
    encrypted = package[8:8 + payload_len]
    salt, token = encrypted[:SALT_SIZE], encrypted[SALT_SIZE:]
    try:
        raw = Fernet(secure_key(passphrase, salt)).decrypt(token)
    except InvalidToken:
        raise ValueError("Incorrect passphrase or the encrypted payload was modified.")
    return json.loads(raw.decode("utf-8"))

def bytes_to_bits(data):
    return "".join(f"{byte:08b}" for byte in data)

def bits_to_bytes(bits):
    usable = len(bits) - (len(bits) % 8)
    return bytes(int(bits[i:i+8], 2) for i in range(0, usable, 8))

def embed_package(package, output_path):
    width, height = DEFAULT_CARD_SIZE
    capacity = width * height // 8
    if len(package) > capacity:
        raise ValueError(
            f"Encrypted payload is {len(package):,} bytes, but this card holds "
            f"only {capacity:,} bytes. Remove some images or use fewer notes."
        )
    image = Image.new("RGB", (width, height), "#111827")
    draw = ImageDraw.Draw(image)
    draw.text((48, 42), "STEGO-VAULT PRO", fill="#93c5fd")
    draw.text((48, 82), "Encrypted vault card • Keep this PNG unchanged", fill="#cbd5e1")
    draw.text((48, 128), f"Created: {datetime.datetime.now():%Y-%m-%d %H:%M:%S}", fill="#94a3b8")
    draw.text((48, 168), "Payload: encrypted", fill="#86efac")
    pixels = image.load()
    bits = bytes_to_bits(package)
    index = 0
    for y in range(height):
        for x in range(width):
            if index >= len(bits):
                break
            r, g, b = pixels[x, y]
            pixels[x, y] = ((r & 0xFE) | int(bits[index]), g, b)
            index += 1
        if index >= len(bits):
            break
    image.save(output_path, format="PNG", optimize=False)

def extract_package(image_path):
    with Image.open(image_path) as source:
        image = source.convert("RGB")
        pixels = image.load()
        width, height = image.size
        header_bits = []
        needed_header = 8 * 8
        for y in range(height):
            for x in range(width):
                header_bits.append(str(pixels[x, y][0] & 1))
                if len(header_bits) == needed_header:
                    break
            if len(header_bits) == needed_header:
                break
        header = bits_to_bytes("".join(header_bits))
        if len(header) < 8 or header[:4] != MAGIC:
            raise ValueError("No Stego-Vault payload was found in this image.")
        payload_len = struct.unpack(">I", header[4:8])[0]
        total_bytes = 8 + payload_len
        if payload_len <= 0 or total_bytes > (width * height // 8):
            raise ValueError("The card header contains an invalid payload size.")
        total_bits = total_bytes * 8
        bits = []
        for y in range(height):
            for x in range(width):
                bits.append(str(pixels[x, y][0] & 1))
                if len(bits) >= total_bits:
                    break
            if len(bits) >= total_bits:
                break
        if len(bits) < total_bits:
            raise ValueError("The image is truncated or has insufficient capacity.")
        return bits_to_bytes("".join(bits))

def write_mv3_extension(target_dir, token, port=BRIDGE_PORT):
    """Generate a ready-to-load Chrome/Edge Manifest V3 extension for the local bridge."""
    ext_path = Path(target_dir)
    ext_path.mkdir(parents=True, exist_ok=True)

    manifest = {
        "manifest_version": 3,
        "name": "Stego-Vault Pro Browser Bridge",
        "version": APP_VERSION,
        "description": "Connects your browser with local Stego-Vault Pro for password intelligence, stego-card probing, and page form/telemetry checks.",
        "permissions": ["activeTab", "scripting", "storage"],
        "host_permissions": ["<all_urls>", f"http://127.0.0.1:{port}/*"],
        "background": {
            "service_worker": "background.js"
        },
        "action": {
            "default_title": "Stego-Vault Pro Bridge",
            "default_popup": "popup.html"
        }
    }

    background_js = f"""const BRIDGE_URL = "http://127.0.0.1:{port}";
const BRIDGE_TOKEN = {json.dumps(token)};

async function postBridge(path, payload) {{
  const res = await fetch(`${{BRIDGE_URL}}${{path}}`, {{
    method: "POST",
    headers: {{
      "Content-Type": "application/json",
      "X-SVP-Token": BRIDGE_TOKEN
    }},
    body: JSON.stringify(payload || {{}})
  }});
  if (!res.ok) {{
    throw new Error(`Bridge HTTP ${{res.status}}`);
  }}
  return await res.json();
}}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {{
  (async () => {{
    try {{
      if (msg.type === "PING") {{
        const res = await fetch(`${{BRIDGE_URL}}/health`, {{
          headers: {{ "X-SVP-Token": BRIDGE_TOKEN }}
        }});
        sendResponse({{ ok: res.ok, data: await res.json() }});
      }} else if (msg.type === "ANALYZE_PASSWORD") {{
        sendResponse({{ ok: true, data: await postBridge("/api/analyze", {{ password: msg.password }}) }});
      }} else if (msg.type === "GENERATE_PASSWORD") {{
        sendResponse({{ ok: true, data: await postBridge("/api/generate", msg.options || {{}}) }});
      }} else if (msg.type === "PAGE_TELEMETRY") {{
        sendResponse({{ ok: true, data: await postBridge("/api/telemetry", msg.report || {{}}) }});
      }} else if (msg.type === "PROBE_IMAGE_B64") {{
        sendResponse({{ ok: true, data: await postBridge("/api/probe-image", {{ image_b64: msg.image_b64 }}) }});
      }} else {{
        sendResponse({{ ok: false, error: "Unknown action" }});
      }}
    }} catch (err) {{
      sendResponse({{ ok: false, error: String(err) }});
    }}
  }})();
  return true;
}});
"""

    popup_html = """<!doctype html>
<html>
<head>
  <meta charset="utf-8" />
  <style>
    body { font-family: Segoe UI, sans-serif; background: #0b1220; color: #e5edf8; width: 320px; padding: 14px; }
    h3 { margin: 0 0 8px 0; color: #60a5fa; font-size: 15px; }
    button { background: #60a5fa; color: #08111f; border: 0; padding: 8px 10px; border-radius: 4px; font-weight: 700; cursor: pointer; width: 100%; margin-top: 6px; }
    button.sec { background: #17243a; color: #e5edf8; }
    pre { background: #111c2e; padding: 8px; border-radius: 4px; font-size: 11px; white-space: pre-wrap; max-height: 210px; overflow: auto; }
  </style>
</head>
<body>
  <h3>Stego-Vault Pro Bridge</h3>
  <button id="scanBtn">Audit Current Tab Forms & Images</button>
  <button id="genBtn" class="sec">Generate Strong Password</button>
  <pre id="out">Checking local bridge...</pre>
  <script src="popup.js"></script>
</body>
</html>
"""

    popup_js = """const out = document.getElementById("out");

async function checkHealth() {
  const resp = await chrome.runtime.sendMessage({ type: "PING" });
  out.textContent = resp && resp.ok ? `Connected: ${JSON.stringify(resp.data)}` : `Bridge offline: ${resp && resp.error}`;
}

document.getElementById("genBtn").addEventListener("click", async () => {
  const resp = await chrome.runtime.sendMessage({
    type: "GENERATE_PASSWORD",
    options: { length: 22, symbols: true, padding_mode: "balanced" }
  });
  if (resp && resp.ok && resp.data.password) {
    await navigator.clipboard.writeText(resp.data.password);
    out.textContent = `Copied (${resp.data.password.length} chars) • Rating: ${resp.data.analysis.rating} (${resp.data.analysis.score}/100)`;
  } else {
    out.textContent = `Error: ${resp && resp.error}`;
  }
});

document.getElementById("scanBtn").addEventListener("click", async () => {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab || !tab.id) return;
  const injected = await chrome.scripting.executeScript({
    target: { tabId: tab.id },
    func: () => {
      const forms = Array.from(document.forms || []);
      const issues = [];
      for (const f of forms) {
        const action = f.getAttribute("action") || location.href;
        const hasPwd = !!f.querySelector("input[type='password']");
        if (hasPwd && action.startsWith("http://")) {
          issues.push("Password form posts over unencrypted HTTP.");
        }
      }
      const imgs = Array.from(document.images || []).slice(0, 8).map(im => ({
        src: im.currentSrc || im.src || "",
        w: im.naturalWidth,
        h: im.naturalHeight
      }));
      return {
        url: location.href,
        origin: location.origin,
        isSecure: window.isSecureContext,
        formCount: forms.length,
        issues,
        sampleImages: imgs
      };
    }
  });
  const pageData = injected[0]?.result || {};
  const tel = await chrome.runtime.sendMessage({ type: "PAGE_TELEMETRY", report: pageData });
  out.textContent = JSON.stringify({ pageData, bridgeAck: tel?.data }, null, 2);
});

checkHealth();
"""

    (ext_path / "manifest.json").write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    (ext_path / "background.js").write_text(background_js, encoding="utf-8")
    (ext_path / "popup.html").write_text(popup_html, encoding="utf-8")
    (ext_path / "popup.js").write_text(popup_js, encoding="utf-8")
    return ext_path


class LocalBrowserBridge:
    """Thread-safe loopback HTTP server allowing a local MV3 extension to talk to Stego-Vault Pro."""

    def __init__(self, app_ref, port=BRIDGE_PORT):
        self.app = app_ref
        self.port = port
        self.token = secrets.token_urlsafe(24)
        self._server = None
        self._thread = None

    def start(self):
        if self._server is not None:
            return
        bridge = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                return

            def _send_json(self, code, payload):
                raw = json.dumps(payload).encode("utf-8")
                self.send_response(code)
                self.send_header("Content-Type", "application/json; charset=utf-8")
                self.send_header("Content-Length", str(len(raw)))
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SVP-Token")
                self.end_headers()
                self.wfile.write(raw)

            def _authorized(self):
                return self.headers.get("X-SVP-Token") == bridge.token

            def do_OPTIONS(self):
                self.send_response(204)
                self.send_header("Access-Control-Allow-Origin", "*")
                self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
                self.send_header("Access-Control-Allow-Headers", "Content-Type, X-SVP-Token")
                self.end_headers()

            def do_GET(self):
                if not self._authorized():
                    self._send_json(401, {"error": "Unauthorized"})
                    return
                if self.path == "/health":
                    self._send_json(200, {
                        "status": "ok",
                        "app": APP_NAME,
                        "version": APP_VERSION,
                        "telemetry_events": len(bridge.app.browser_telemetry)
                    })
                else:
                    self._send_json(404, {"error": "Not found"})

            def do_POST(self):
                if not self._authorized():
                    self._send_json(401, {"error": "Unauthorized"})
                    return
                try:
                    length = int(self.headers.get("Content-Length", "0"))
                except ValueError:
                    length = 0
                if length > MAX_IMPORT_BYTES:
                    self._send_json(413, {"error": "Payload too large"})
                    return
                body = self.rfile.read(length) if length > 0 else b"{}"
                try:
                    data = json.loads(body.decode("utf-8"))
                except Exception:
                    self._send_json(400, {"error": "Invalid JSON"})
                    return

                if self.path == "/api/analyze":
                    pwd = str(data.get("password", ""))
                    self._send_json(200, analyze_password(pwd))

                elif self.path == "/api/generate":
                    try:
                        pwd = generate_adaptive_password(
                            length=int(data.get("length", 20)),
                            symbols=bool(data.get("symbols", True)),
                            base_words=str(data.get("base_words", "")),
                            use_mixed_scripts=bool(data.get("use_mixed_scripts", False)),
                            padding_mode=str(data.get("padding_mode", "balanced"))
                        )
                        self._send_json(200, {
                            "password": pwd,
                            "analysis": analyze_password(pwd)
                        })
                    except Exception as exc:
                        self._send_json(400, {"error": str(exc)})

                elif self.path == "/api/telemetry":
                    event = {
                        "ts": datetime.datetime.now().strftime("%H:%M:%S"),
                        "origin": str(data.get("origin", "unknown")),
                        "isSecure": bool(data.get("isSecure", True)),
                        "formCount": int(data.get("formCount", 0)),
                        "issues": list(data.get("issues", []))[:10]
                    }
                    bridge.app.root.after(0, lambda ev=event: bridge.app.record_browser_telemetry(ev))
                    self._send_json(200, {"recorded": True})

                elif self.path == "/api/probe-image":
                    try:
                        b64_str = str(data.get("image_b64", ""))
                        if "," in b64_str:
                            b64_str = b64_str.split(",", 1)[1]
                        raw_img = base64.b64decode(b64_str, validate=True)
                        tmp_probe = DATA_DIR / "bridge_probe_temp.png"
                        tmp_probe.write_bytes(raw_img)
                        try:
                            pkg = extract_package(tmp_probe)
                            self._send_json(200, {
                                "has_stego_payload": True,
                                "encrypted_bytes": len(pkg)
                            })
                        except Exception:
                            self._send_json(200, {
                                "has_stego_payload": False,
                                "encrypted_bytes": 0
                            })
                        finally:
                            if tmp_probe.exists():
                                tmp_probe.unlink()
                    except Exception as exc:
                        self._send_json(400, {"error": str(exc)})
                else:
                    self._send_json(404, {"error": "Unknown endpoint"})

        self._server = ThreadingHTTPServer((BRIDGE_HOST, self.port), Handler)
        self._thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._thread.start()
        log.info("Browser bridge started on %s:%d", BRIDGE_HOST, self.port)

    def stop(self):
        if self._server is not None:
            try:
                self._server.shutdown()
                self._server.server_close()
            except Exception:
                pass
            self._server = None
            self._thread = None
            log.info("Browser bridge stopped")


class StegoVaultApp:
    BG = "#0b1220"
    PANEL = "#111c2e"
    PANEL2 = "#17243a"
    TEXT = "#e5edf8"
    MUTED = "#9aabc2"
    BLUE = "#60a5fa"
    GREEN = "#4ade80"
    RED = "#fb7185"
    AMBER = "#fbbf24"

    def __init__(self, root):
        self.root = root
        self.root.title(f"Stego-Vault Pro {APP_VERSION} — Secure Studio")
        self.root.geometry("1060x820")
        self.root.minsize(840, 650)
        self.root.configure(bg=self.BG)

        saved = load_settings()

        self.selected_files = []
        self.generated_password_value = ""
        self.batch_passwords = []
        self.browser_telemetry = []
        self.altered_state_var = tk.StringVar(
            value=str(saved.get("altered_state", "Baseline Focus"))
            if str(saved.get("altered_state", "Baseline Focus")) in ALTERED_STATES_MODES
            else "Baseline Focus"
        )
        self.show_full_password = tk.BooleanVar(value=False)
        self.multilingual_var = tk.BooleanVar(value=bool(saved.get("multilingual", False)))
        self.exclude_ambiguous_var = tk.BooleanVar(value=bool(saved.get("exclude_ambiguous", False)))
        self.lab_mixed_scripts_var = tk.BooleanVar(value=bool(saved.get("lab_mixed_scripts", False)))
        self.lab_symbols_var = tk.BooleanVar(value=bool(saved.get("lab_symbols", True)))
        self.lab_exclude_ambig_var = tk.BooleanVar(value=bool(saved.get("lab_exclude_ambig", False)))
        self.phrase_words_var = tk.IntVar(value=int(saved.get("phrase_words", 4)))
        self.phrase_sep_var = tk.StringVar(value=str(saved.get("phrase_sep", "-")))
        self.phrase_cap_var = tk.BooleanVar(value=bool(saved.get("phrase_cap", True)))
        self.phrase_num_var = tk.BooleanVar(value=bool(saved.get("phrase_num", True)))
        self.clipboard_autoclean_var = tk.BooleanVar(value=bool(saved.get("clipboard_autoclean", True)))
        self.clipboard_clear_seconds = tk.IntVar(value=int(saved.get("clipboard_clear_seconds", 20)))
        self.bridge_enabled_var = tk.BooleanVar(value=False)
        self.current_qr = None
        self.qr_photo = None
        self.camera_enabled = tk.BooleanVar(value=False)
        self.symbols_var = tk.BooleanVar(value=bool(saved.get("symbols", True)))
        self.hardware_lock_var = tk.BooleanVar(value=bool(saved.get("hardware_lock", False)))
        self._camera = None
        self._camera_window = False
        self._clipboard_after_id = None
        self._last_copied_secret = None
        self.bridge = LocalBrowserBridge(self, port=BRIDGE_PORT)

        self._build_style()
        self._build_ui()
        self.apply_altered_state(announce=False)
        self.refresh_capacity_forecast()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.set_status("Ready • Standalone local vault active (Browser Bridge is OFF by default).")
        log.info("Application started")

    def _build_style(self):
        style = ttk.Style()
        try:
            style.theme_use("clam")
        except tk.TclError:
            pass
        style.configure("TNotebook", background=self.BG, borderwidth=0)
        style.configure(
            "TNotebook.Tab", background=self.PANEL2, foreground=self.TEXT,
            padding=(13, 10), font=("Segoe UI", 9, "bold")
        )
        style.map("TNotebook.Tab",
                  background=[("selected", self.BLUE)],
                  foreground=[("selected", "#08111f")])
        style.configure("TProgressbar", troughcolor=self.PANEL2, background=self.GREEN)

    def _build_ui(self):
        header = tk.Frame(self.root, bg=self.BG)
        header.pack(fill="x", padx=22, pady=(18, 10))
        tk.Label(header, text="🔐 STEGO-VAULT PRO", bg=self.BG, fg=self.TEXT,
                 font=("Segoe UI", 20, "bold")).pack(anchor="w")
        tk.Label(header, text="SECURE STUDIO  •  ENCRYPT  •  EMBED  •  RECOVER  •  SECURITY LAB  •  BROWSER BRIDGE  •  TRANSFER",
                 bg=self.BG, fg=self.BLUE, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 0))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=8)
        self.gen_tab = tk.Frame(self.notebook, bg=self.BG)
        self.dec_tab = tk.Frame(self.notebook, bg=self.BG)
        self.lab_tab = tk.Frame(self.notebook, bg=self.BG)
        self.bridge_tab = tk.Frame(self.notebook, bg=self.BG)
        self.qr_tab = tk.Frame(self.notebook, bg=self.BG)
        self.settings_tab = tk.Frame(self.notebook, bg=self.BG)

        self.notebook.add(self.gen_tab, text="  CREATE VAULT  ")
        self.notebook.add(self.dec_tab, text="  UNLOCK / EXTRACT  ")
        self.notebook.add(self.lab_tab, text="  SECURITY LAB  ")
        self.notebook.add(self.bridge_tab, text="  BROWSER BRIDGE  ")
        self.notebook.add(self.qr_tab, text="  QR TRANSFER  ")
        self.notebook.add(self.settings_tab, text="  SETTINGS / DIAGNOSTICS  ")

        self._build_generator()
        self._build_decoder()
        self._build_security_lab()
        self._build_browser_bridge()
        self._build_qr()
        self._build_settings()

        footer = tk.Frame(self.root, bg=self.PANEL, height=38)
        footer.pack(fill="x", side="bottom")
        self.status_label = tk.Label(footer, text="", bg=self.PANEL, fg=self.GREEN,
                                     font=("Segoe UI", 9), anchor="w")
        self.status_label.pack(fill="x", padx=16, pady=9)

    def panel(self, parent, title):
        frame = tk.LabelFrame(parent, text=f"  {title}  ", bg=self.PANEL,
                              fg=self.BLUE, font=("Segoe UI", 10, "bold"),
                              bd=1, relief="solid", padx=14, pady=10)
        frame.pack(fill="x", padx=18, pady=8)
        return frame

    def label(self, parent, text):
        tk.Label(parent, text=text, bg=self.PANEL, fg=self.TEXT,
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(4, 3))

    def entry(self, parent, show=None):
        e = tk.Entry(parent, show=show, bg=self.PANEL2, fg=self.TEXT,
                     insertbackground=self.TEXT, relief="flat",
                     font=("Segoe UI", 10))
        e.pack(fill="x", ipady=7, pady=(0, 5))
        return e

    def button(self, parent, text, command, primary=False):
        return tk.Button(
            parent, text=text, command=command,
            bg=self.BLUE if primary else self.PANEL2,
            fg="#08111f" if primary else self.TEXT,
            activebackground="#93c5fd", activeforeground="#08111f",
            relief="flat", bd=0, padx=13, pady=8,
            font=("Segoe UI", 9, "bold"), cursor="hand2"
        )

    # ---- Clipboard self-cleaning helpers ------------------------------------
    def copy_secret_with_autoclean(self, secret_value, label="Secret"):
        if not secret_value:
            return False
        if self._clipboard_after_id is not None:
            try:
                self.root.after_cancel(self._clipboard_after_id)
            except Exception:
                pass
            self._clipboard_after_id = None

        self._last_copied_secret = secret_value
        self.root.clipboard_clear()
        self.root.clipboard_append(secret_value)
        self.root.update()

        if self.clipboard_autoclean_var.get():
            try:
                seconds = max(5, min(600, int(self.clipboard_clear_seconds.get())))
            except (ValueError, tk.TclError):
                seconds = 20
            expected = secret_value
            self._clipboard_after_id = self.root.after(
                seconds * 1000,
                lambda val=expected: self._clear_clipboard_if_unchanged(val)
            )
            self.set_status(
                f"{label} copied to clipboard (auto-clears in {seconds}s if still current)."
            )
        else:
            self.set_status(f"{label} copied to clipboard (auto-clear disabled).")
        return True

    def _clear_clipboard_if_unchanged(self, expected_value):
        self._clipboard_after_id = None
        try:
            current = self.root.clipboard_get()
        except tk.TclError:
            return
        if current == expected_value and expected_value == self._last_copied_secret:
            try:
                self.root.clipboard_clear()
                self.root.update()
                self._last_copied_secret = None
                self.set_status("Copied secret cleared from clipboard after timeout.")
            except tk.TclError:
                pass

    # ---- Tab 1: Create Vault ----------------------------------------------
    def _build_generator(self):
        f = self.panel(self.gen_tab, "VAULT CONTENT")
        self.label(f, "Optional note / secret text")
        self.payload_entry = self.entry(f)
        self.payload_entry.insert(0, "Private note")
        self.payload_entry.bind("<KeyRelease>", lambda _e: self.refresh_capacity_forecast())
        self.label(f, "Master passphrase (10+ characters)")
        self.master_entry = self.entry(f, show="•")
        self.label(f, "Confirm master passphrase")
        self.confirm_entry = self.entry(f, show="•")
        opts = tk.Frame(f, bg=self.PANEL)
        opts.pack(fill="x", pady=5)
        tk.Checkbutton(opts, text="Include hardware lock (same-machine restriction)",
                       variable=self.hardware_lock_var, bg=self.PANEL, fg=self.TEXT,
                       selectcolor=self.PANEL2, activebackground=self.PANEL,
                       activeforeground=self.TEXT).pack(anchor="w")
        self.label(f, "Attach small image files (optional)")
        file_row = tk.Frame(f, bg=self.PANEL)
        file_row.pack(fill="x")
        self.file_count = tk.Label(file_row, text="No files selected",
                                   bg=self.PANEL, fg=self.MUTED)
        self.file_count.pack(side="left")
        self.button(file_row, "Add files", self.add_files).pack(side="right", padx=3)
        self.button(file_row, "Clear", self.clear_files).pack(side="right", padx=3)

        self.capacity_lbl = tk.Label(
            f, text="", bg=self.PANEL, fg=self.BLUE,
            font=("Segoe UI", 9, "bold"), wraplength=880, justify="left"
        )
        self.capacity_lbl.pack(anchor="w", pady=(6, 0))

        p = self.panel(self.gen_tab, "QUICK PASSWORD GENERATOR")
        row = tk.Frame(p, bg=self.PANEL)
        row.pack(fill="x")
        tk.Label(row, text="Length", bg=self.PANEL, fg=self.TEXT).pack(side="left")
        self.password_length = tk.IntVar(value=24)
        tk.Spinbox(row, from_=8, to=256, textvariable=self.password_length,
                   width=7, bg=self.PANEL2, fg=self.TEXT,
                   buttonbackground=self.PANEL2).pack(side="left", padx=10)
        tk.Checkbutton(row, text="Symbols", variable=self.symbols_var,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(side="left")
        tk.Checkbutton(row, text="Exclude ambiguous (0/O/1/l/I)",
                       variable=self.exclude_ambiguous_var,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(side="left", padx=10)
        lang_row = tk.Frame(p, bg=self.PANEL)
        lang_row.pack(fill="x", pady=(5, 2))
        tk.Checkbutton(
            lang_row, text="Enable mixed-language / mixed-script characters",
            variable=self.multilingual_var, bg=self.PANEL, fg=self.TEXT,
            selectcolor=self.PANEL2, activebackground=self.PANEL,
            activeforeground=self.TEXT, command=self.update_password_preview
        ).pack(side="left")
        self.language_hint = tk.Label(
            p, text=f"Default: standard characters ({detect_system_language()} system locale detected). "
                    "Mixed-script mode is optional and may not work on every website.",
            bg=self.PANEL, fg=self.MUTED, wraplength=880, justify="left"
        )
        self.language_hint.pack(anchor="w", pady=(2, 5))

        self.generated_password = tk.Entry(
            p, bg=self.PANEL2, fg=self.TEXT, insertbackground=self.TEXT,
            relief="flat", font=("Consolas", 10)
        )
        self.generated_password.pack(fill="x", ipady=7, pady=8)

        mask_row = tk.Frame(p, bg=self.PANEL)
        mask_row.pack(fill="x", pady=(0, 5))
        tk.Label(mask_row, text="Visible characters:", bg=self.PANEL,
                 fg=self.TEXT).pack(side="left")
        self.visible_chars = tk.IntVar(value=10)
        visible_spin = tk.Spinbox(mask_row, from_=0, to=256, width=5,
                                  textvariable=self.visible_chars,
                                  command=self.update_password_preview,
                                  bg=self.PANEL2, fg=self.TEXT,
                                  buttonbackground=self.PANEL2)
        visible_spin.pack(side="left", padx=8)
        visible_spin.bind("<KeyRelease>", self.update_password_preview)
        tk.Checkbutton(
            mask_row, text="Temporarily show full password",
            variable=self.show_full_password, bg=self.PANEL, fg=self.TEXT,
            selectcolor=self.PANEL2, activebackground=self.PANEL,
            command=self.update_password_preview
        ).pack(side="left", padx=8)
        tk.Label(
            p, text="The hidden characters are still part of the real password. "
                   "Copy password copies the complete value, not the masked preview.",
            bg=self.PANEL, fg=self.MUTED, wraplength=880, justify="left"
        ).pack(anchor="w", pady=(0, 5))

        row2 = tk.Frame(p, bg=self.PANEL)
        row2.pack(fill="x")
        self.button(row2, "Generate password", self.make_password).pack(side="left")
        self.button(row2, "Copy FULL password", self.copy_generated).pack(side="left", padx=7)

        self.button(self.gen_tab, "🔒 ENCRYPT & CREATE PNG VAULT CARD",
                    self.create_vault, primary=True).pack(fill="x", padx=18, pady=12)

    # ---- Tab 2: Unlock / Extract ------------------------------------------
    def _build_decoder(self):
        f = self.panel(self.dec_tab, "SELECT VAULT CARD")
        row = tk.Frame(f, bg=self.PANEL)
        row.pack(fill="x")
        self.card_path = tk.Entry(row, bg=self.PANEL2, fg=self.TEXT,
                                  insertbackground=self.TEXT, relief="flat")
        self.card_path.pack(side="left", fill="x", expand=True, ipady=8)
        self.button(row, "Browse PNG", self.browse_card).pack(side="left", padx=(8, 0))
        self.button(row, "Audit Card (APEX/VANTA)", self.audit_selected_card).pack(side="left", padx=(6, 0))
        self.label(f, "Master passphrase")
        self.decode_pass = self.entry(f, show="•")
        self.button(f, "🔓 DECRYPT & EXTRACT", self.unlock_card, primary=True).pack(
            fill="x", pady=8
        )
        out = self.panel(self.dec_tab, "DECRYPTED CONTENT & CARD AUDIT")
        self.dec_output = tk.Text(out, height=12, bg=self.PANEL2, fg=self.TEXT,
                                  insertbackground=self.TEXT, relief="flat",
                                  wrap="word", font=("Consolas", 10))
        self.dec_output.pack(fill="both", expand=True)
        self.button(out, "Save extracted note", self.save_extracted_note).pack(
            anchor="e", pady=(8, 0)
        )

    # ---- Tab 3: Security Lab ----------------------------------------------
    def _build_security_lab(self):
        canvas = tk.Canvas(self.lab_tab, bg=self.BG, highlightthickness=0)
        scrollbar = ttk.Scrollbar(self.lab_tab, orient="vertical", command=canvas.yview)
        inner = tk.Frame(canvas, bg=self.BG)

        inner.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        win_id = canvas.create_window((0, 0), window=inner, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        canvas.bind(
            "<Configure>",
            lambda e: canvas.itemconfig(win_id, width=e.width)
        )

        canvas.pack(side="left", fill="both", expand=True)
        scrollbar.pack(side="right", fill="y")

        # Altered States & ChronoMind bar
        state_panel = self.panel(inner, "ALTERED STATES & CHRONOMIND NEXUS")
        st_row = tk.Frame(state_panel, bg=self.PANEL)
        st_row.pack(fill="x")
        tk.Label(st_row, text="State Mode:", bg=self.PANEL, fg=self.TEXT,
                 font=("Segoe UI", 9, "bold")).pack(side="left")
        state_combo = ttk.Combobox(
            st_row, textvariable=self.altered_state_var,
            values=list(ALTERED_STATES_MODES.keys()),
            state="readonly", width=26
        )
        state_combo.pack(side="left", padx=(6, 10))
        state_combo.bind("<<ComboboxSelected>>", lambda _e: self.apply_altered_state(announce=True))
        self.button(st_row, "Check Time Integrity", self.run_time_integrity_check).pack(side="left")
        self.altered_state_desc = tk.Label(
            state_panel, text="", bg=self.PANEL, fg=self.MUTED,
            wraplength=900, justify="left"
        )
        self.altered_state_desc.pack(anchor="w", pady=(5, 0))

        adapt = self.panel(inner, "ADAPTIVE PASSWORD & PASSPHRASE GENERATOR")
        top_row = tk.Frame(adapt, bg=self.PANEL)
        top_row.pack(fill="x", pady=(0, 6))

        tk.Label(top_row, text="Length:", bg=self.PANEL, fg=self.TEXT).pack(side="left")
        self.lab_length = tk.IntVar(value=20)
        tk.Spinbox(top_row, from_=8, to=256, textvariable=self.lab_length, width=6,
                   bg=self.PANEL2, fg=self.TEXT, buttonbackground=self.PANEL2).pack(side="left", padx=(4, 14))

        tk.Label(top_row, text="Padding:", bg=self.PANEL, fg=self.TEXT).pack(side="left")
        self.padding_mode_var = tk.StringVar(value="balanced")
        pad_combo = ttk.Combobox(top_row, textvariable=self.padding_mode_var,
                                   values=["minimal", "balanced", "heavy"],
                                   state="readonly", width=10)
        pad_combo.pack(side="left", padx=(4, 14))

        tk.Checkbutton(top_row, text="Include symbols", variable=self.lab_symbols_var,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(side="left", padx=(0, 10))
        tk.Checkbutton(top_row, text="Mixed scripts", variable=self.lab_mixed_scripts_var,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(side="left", padx=(0, 10))
        tk.Checkbutton(top_row, text="No ambiguous", variable=self.lab_exclude_ambig_var,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(side="left")

        phrase_row = tk.Frame(adapt, bg=self.PANEL)
        phrase_row.pack(fill="x", pady=(4, 4))
        tk.Label(phrase_row, text="Passphrase words:", bg=self.PANEL, fg=self.TEXT).pack(side="left")
        tk.Spinbox(phrase_row, from_=2, to=12, textvariable=self.phrase_words_var, width=4,
                   bg=self.PANEL2, fg=self.TEXT, buttonbackground=self.PANEL2).pack(side="left", padx=(4, 10))
        tk.Label(phrase_row, text="Sep:", bg=self.PANEL, fg=self.TEXT).pack(side="left")
        tk.Entry(phrase_row, textvariable=self.phrase_sep_var, width=4,
                 bg=self.PANEL2, fg=self.TEXT, insertbackground=self.TEXT, relief="flat").pack(side="left", padx=(4, 10))
        tk.Checkbutton(phrase_row, text="Capitalize words", variable=self.phrase_cap_var,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(side="left", padx=(0, 10))
        tk.Checkbutton(phrase_row, text="Append number", variable=self.phrase_num_var,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(side="left", padx=(0, 10))
        self.button(phrase_row, "Generate word passphrase", self.run_word_passphrase).pack(side="right")

        self.label(adapt, "Optional base words (comma, space, or newline separated)")
        self.base_words_entry = self.entry(adapt)
        self.base_words_entry.insert(0, "")

        self.label(adapt, "Generated adaptive password / passphrase (also feeds strength analyzer)")
        self.lab_password_entry = self.entry(adapt)

        btn_row = tk.Frame(adapt, bg=self.PANEL)
        btn_row.pack(fill="x", pady=(4, 0))
        self.button(btn_row, "Generate adaptive password", self.run_adaptive_generation, primary=True).pack(side="left")
        self.button(btn_row, "Analyze & forecast", self.run_password_analysis).pack(side="left", padx=8)
        self.button(btn_row, "Copy with auto-clean", self.copy_lab_password).pack(side="left")

        intel = self.panel(inner, "PARALLAX SWARM & PREDICTIVE INTELLIGENCE")
        self.intel_summary = tk.Label(
            intel, text="Rating: —  |  Estimated Entropy: —  |  Repetition: —",
            bg=self.PANEL, fg=self.BLUE, font=("Segoe UI", 10, "bold")
        )
        self.intel_summary.pack(anchor="w", pady=(0, 4))
        self.intel_output = tk.Text(intel, height=12, bg=self.PANEL2, fg=self.TEXT,
                                    insertbackground=self.TEXT, relief="flat",
                                    wrap="word", font=("Consolas", 9))
        self.intel_output.pack(fill="both", expand=True)

        clip = self.panel(inner, "CLIPBOARD SELF-CLEANING")
        clip_row = tk.Frame(clip, bg=self.PANEL)
        clip_row.pack(fill="x")
        tk.Checkbutton(
            clip_row, text="Auto-clear copied passwords after interval",
            variable=self.clipboard_autoclean_var, bg=self.PANEL, fg=self.TEXT,
            selectcolor=self.PANEL2, activebackground=self.PANEL
        ).pack(side="left")
        tk.Label(clip_row, text="Delay (sec):", bg=self.PANEL, fg=self.TEXT).pack(side="left", padx=(16, 4))
        tk.Spinbox(clip_row, from_=5, to=600, textvariable=self.clipboard_clear_seconds,
                   width=6, bg=self.PANEL2, fg=self.TEXT,
                   buttonbackground=self.PANEL2).pack(side="left")
        self.button(clip_row, "Clear clipboard now", self.clear_clipboard_manual).pack(side="right")
        tk.Label(
            clip, text="Only erases the clipboard if its current content still matches the last secret "
                       "copied by Stego-Vault Pro—newer clipboard items are left untouched.",
            bg=self.PANEL, fg=self.MUTED, wraplength=900, justify="left"
        ).pack(anchor="w", pady=(5, 0))

        batch = self.panel(inner, "BATCH PASSWORD GENERATOR (UP TO 100)")
        batch_ctrl = tk.Frame(batch, bg=self.PANEL)
        batch_ctrl.pack(fill="x", pady=(0, 6))
        tk.Label(batch_ctrl, text="Count (1–100):", bg=self.PANEL, fg=self.TEXT).pack(side="left")
        self.batch_count_var = tk.IntVar(value=25)
        tk.Spinbox(batch_ctrl, from_=1, to=100, textvariable=self.batch_count_var,
                   width=6, bg=self.PANEL2, fg=self.TEXT,
                   buttonbackground=self.PANEL2).pack(side="left", padx=(6, 12))
        self.button(batch_ctrl, "Generate batch", self.run_batch_generation, primary=True).pack(side="left")
        self.button(batch_ctrl, "Export TXT", lambda: self.export_batch("txt")).pack(side="left", padx=8)
        self.button(batch_ctrl, "Export CSV", lambda: self.export_batch("csv")).pack(side="left")

        self.batch_output = tk.Text(batch, height=8, bg=self.PANEL2, fg=self.TEXT,
                                    insertbackground=self.TEXT, relief="flat",
                                    wrap="none", font=("Consolas", 9))
        self.batch_output.pack(fill="both", expand=True)

    # ---- Tab 4: Browser Bridge --------------------------------------------
    def _build_browser_bridge(self):
        ctrl = self.panel(self.bridge_tab, "LOCAL BROWSER BRIDGE (127.0.0.1)")
        top = tk.Frame(ctrl, bg=self.PANEL)
        top.pack(fill="x")
        tk.Checkbutton(
            top, text="Enable local bridge server for browser extension",
            variable=self.bridge_enabled_var, command=self.toggle_bridge,
            bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
            activebackground=self.PANEL, font=("Segoe UI", 9, "bold")
        ).pack(side="left")
        self.button(top, "Build MV3 Extension Files", self.build_extension_bundle, primary=True).pack(side="right")

        self.bridge_status_lbl = tk.Label(
            ctrl, text=f"Bridge: OFF  •  Port: {BRIDGE_PORT}  •  Extension folder: {EXTENSION_DIR}",
            bg=self.PANEL, fg=self.MUTED, wraplength=900, justify="left"
        )
        self.bridge_status_lbl.pack(anchor="w", pady=(6, 4))

        tk.Label(
            ctrl,
            text="Keep this off when you want strictly standalone local-only operation. "
                 "If enabled, load the generated folder in Chrome/Edge via Extensions → Developer mode → Load unpacked; "
                 "rebuilding after restarting updates the session token in background.js.",
            bg=self.PANEL, fg=self.MUTED, wraplength=900, justify="left"
        ).pack(anchor="w")

        telem = self.panel(self.bridge_tab, "LIVE BROWSER TELEMETRY & FORM GUARD")
        t_btns = tk.Frame(telem, bg=self.PANEL)
        t_btns.pack(fill="x", pady=(0, 6))
        self.button(t_btns, "Clear telemetry log", self.clear_browser_telemetry).pack(side="left")

        self.telemetry_output = tk.Text(
            telem, height=14, bg=self.PANEL2, fg=self.TEXT,
            insertbackground=self.TEXT, relief="flat", wrap="word", font=("Consolas", 9)
        )
        self.telemetry_output.pack(fill="both", expand=True)

    # ---- Tab 5: QR Transfer -----------------------------------------------
    def _build_qr(self):
        f = self.panel(self.qr_tab, "QR CODE TRANSFER")
        tk.Label(f, text="Paste text or an encrypted vault package (Base64) to encode.",
                 bg=self.PANEL, fg=self.MUTED).pack(anchor="w")
        self.qr_input = tk.Text(f, height=5, bg=self.PANEL2, fg=self.TEXT,
                                insertbackground=self.TEXT, relief="flat",
                                wrap="word", font=("Consolas", 9))
        self.qr_input.pack(fill="x", pady=8)
        row = tk.Frame(f, bg=self.PANEL)
        row.pack(fill="x")
        self.button(row, "Generate QR", self.make_qr, primary=True).pack(side="left")
        self.button(row, "Save QR PNG", self.save_qr).pack(side="left", padx=8)
        self.button(row, "Load text file", self.load_qr_text).pack(side="left")
        self.qr_preview = tk.Label(f, text="QR preview appears here",
                                   bg=self.PANEL2, fg=self.MUTED,
                                   width=36, height=16)
        self.qr_preview.pack(pady=12)

        cam = self.panel(self.qr_tab, "WEBCAM QR SCANNER")
        tk.Checkbutton(cam, text="Enable webcam access (optional)",
                       variable=self.camera_enabled, command=self.toggle_camera,
                       bg=self.PANEL, fg=self.TEXT, selectcolor=self.PANEL2,
                       activebackground=self.PANEL).pack(anchor="w")
        self.camera_status = tk.Label(cam, text="Camera is off",
                                      bg=self.PANEL, fg=self.MUTED)
        self.camera_status.pack(anchor="w", pady=4)
        self.button(cam, "Scan QR with webcam", self.scan_webcam).pack(anchor="w")

    # ---- Tab 6: Settings & Diagnostics ------------------------------------
    def _build_settings(self):
        f = self.panel(self.settings_tab, "APPLICATION STATUS")
        self.admin_label = tk.Label(f, text="", bg=self.PANEL, fg=self.GREEN,
                                    font=("Segoe UI", 10, "bold"))
        self.admin_label.pack(anchor="w", pady=4)
        tk.Label(f, text=f"Data directory: {DATA_DIR}",
                 bg=self.PANEL, fg=self.TEXT, wraplength=900,
                 justify="left").pack(anchor="w", pady=4)
        tk.Label(f, text=f"Audit log: {LOG_PATH}",
                 bg=self.PANEL, fg=self.MUTED, wraplength=900,
                 justify="left").pack(anchor="w", pady=4)
        tk.Label(f, text=f"Preferences file: {SETTINGS_PATH}",
                 bg=self.PANEL, fg=self.MUTED, wraplength=900,
                 justify="left").pack(anchor="w", pady=4)
        self.refresh_admin_status()
        row = tk.Frame(f, bg=self.PANEL)
        row.pack(fill="x", pady=8)
        self.button(row, "Restart as Administrator", self.restart_admin).pack(side="left")
        self.button(row, "Open data folder", self.open_data_folder).pack(side="left", padx=8)
        self.button(row, "Test write permissions", self.test_permissions).pack(side="left")
        tk.Label(f,
                 text=("Administrator rights are normally NOT required. "
                       "The app stores its files in your user profile. "
                       "Only elevate if a separate protected system resource requires it."),
                 bg=self.PANEL, fg=self.MUTED, wraplength=900,
                 justify="left").pack(anchor="w", pady=8)

        g = self.panel(self.settings_tab, "SECURITY & COMPATIBILITY DIAGNOSTICS")
        notes = [
            "Encryption: Fernet authenticated encryption with PBKDF2-HMAC-SHA256.",
            f"Key derivation: {KDF_ITERATIONS:,} iterations per unlock.",
            "Card format: PNG least-significant-bit payload; keep the original PNG unchanged.",
            "No plaintext passphrase is saved. There is no silent auto-unlock.",
            "Hardware lock is a portability restriction, not a substitute for encryption.",
            "Webcam face detection is not identity verification and is not used to unlock vaults.",
            "Local scope: Stego-Vault Pro operates on data you explicitly place into vaults or export; leave the Browser Bridge off if you do not want local browser extension traffic.",
            "Predictive & physics models: Crack-time estimates, Parallax Swarm consensus, and Water-Data flow readouts are deterministic mathematical/simulation models—not guarantees.",
            "Unicode compatibility: Mixed-script or non-ASCII passwords can fail input filters, normalization (NFC/NFD), or keyboard layouts on some websites/apps.",
            "Clipboard history risk: OS clipboard history features (such as Windows Clipboard History) or background apps may retain copied secrets even after active clipboard clearing.",
            "Password storage risk: Exported password batches or unencrypted notes are sensitive secrets—store them in an encrypted vault or protected medium and delete temporary files when finished."
        ]
        for item in notes:
            tk.Label(g, text="• " + item, bg=self.PANEL, fg=self.TEXT,
                     wraplength=900, justify="left").pack(anchor="w", pady=3)

    # ---- Altered States & ChronoMind Actions -----------------------------
    def apply_altered_state(self, announce=True):
        mode_name = self.altered_state_var.get()
        cfg = ALTERED_STATES_MODES.get(mode_name, ALTERED_STATES_MODES["Baseline Focus"])
        if hasattr(self, "altered_state_desc"):
            self.altered_state_desc.config(text=cfg["description"])
        if announce:
            self.password_length.set(cfg["password_len"])
            self.lab_length.set(cfg["password_len"])
            self.phrase_words_var.set(cfg["phrase_words"])
            self.clipboard_clear_seconds.set(cfg["clipboard_sec"])
            log.info("Altered State applied: %s", mode_name)
            self.set_status(f"Altered State active: {mode_name} (len={cfg['password_len']}, clip={cfg['clipboard_sec']}s).")

    def run_time_integrity_check(self):
        info = check_time_integrity()
        msg = (
            f"ChronoMind Time Integrity: {info['status']}\n"
            f"Local: {info['local_iso']} (UTC{info['utc_offset_hours']:+.2f}h)\n"
            f"UTC:   {info['utc_iso']}\n"
            f"Monotonic clock OK: {info['monotonic_ok']}"
        )
        self.set_status(f"ChronoMind: {info['status']} • {info['local_iso']}")
        messagebox.showinfo("ChronoMind Nexus — Time Check", msg)

    # ---- Browser Bridge Actions -------------------------------------------
    def toggle_bridge(self):
        if self.bridge_enabled_var.get():
            try:
                self.bridge.start()
                self.bridge_status_lbl.config(
                    text=f"Bridge: LISTENING on http://{BRIDGE_HOST}:{BRIDGE_PORT}  •  Folder: {EXTENSION_DIR}",
                    fg=self.GREEN
                )
                self.set_status("Local Browser Bridge started.")
            except Exception as exc:
                self.bridge_enabled_var.set(False)
                messagebox.showerror("Bridge error", f"Could not start local bridge:\n{exc}")
        else:
            self.bridge.stop()
            self.bridge_status_lbl.config(
                text=f"Bridge: OFF  •  Port: {BRIDGE_PORT}  •  Extension folder: {EXTENSION_DIR}",
                fg=self.MUTED
            )
            self.set_status("Local Browser Bridge stopped.")

    def build_extension_bundle(self):
        try:
            out = write_mv3_extension(EXTENSION_DIR, self.bridge.token, port=self.bridge.port)
            log.info("Generated MV3 extension bundle at %s", out)
            self.set_status(f"Browser extension bundle ready: {out}")
            messagebox.showinfo(
                "Extension Ready",
                f"Manifest V3 extension files written to:\n{out}\n\n"
                "Load unpacked in Chrome/Edge and enable the Local Browser Bridge toggle."
            )
        except Exception as exc:
            messagebox.showerror("Extension build error", str(exc))

    def record_browser_telemetry(self, event):
        self.browser_telemetry.append(event)
        issues_txt = "; ".join(event["issues"]) if event["issues"] else "No obvious form warnings"
        line = (
            f"[{event['ts']}] {event['origin']} | secure={event['isSecure']} | "
            f"forms={event['formCount']} | {issues_txt}\n"
        )
        self.telemetry_output.insert(tk.END, line)
        self.telemetry_output.see(tk.END)

    def clear_browser_telemetry(self):
        self.browser_telemetry.clear()
        self.telemetry_output.delete("1.0", tk.END)
        self.set_status("Browser telemetry log cleared.")

    # ---- Status & System Actions ------------------------------------------
    def set_status(self, text, color=None):
        self.status_label.config(text=text, fg=color or self.GREEN)

    def refresh_admin_status(self):
        state = "RUNNING AS ADMINISTRATOR" if is_admin() else "STANDARD USER — RECOMMENDED"
        self.admin_label.config(text=state, fg=self.GREEN if not is_admin() else self.BLUE)

    def restart_admin(self):
        if os.name != "nt":
            messagebox.showinfo("Administrator", "Elevation is only available on Windows.")
            return
        try:
            params = subprocess.list2cmdline(sys.argv)
            result = ctypes.windll.shell32.ShellExecuteW(
                None, "runas", sys.executable, params, None, 1
            )
            if result <= 32:
                raise OSError(f"ShellExecuteW returned {result}")
            self.root.after(300, self.root.destroy)
        except Exception as exc:
            messagebox.showerror("Elevation failed", f"Could not restart elevated:\n{exc}")

    def open_data_folder(self):
        try:
            if os.name == "nt":
                os.startfile(str(DATA_DIR))
            else:
                subprocess.Popen(["xdg-open", str(DATA_DIR)])
        except Exception as exc:
            messagebox.showerror("Folder error", str(exc))

    def test_permissions(self):
        try:
            probe = DATA_DIR / "permission_test.tmp"
            probe.write_text("write test", encoding="utf-8")
            probe.unlink()
            self.set_status("Permission test passed — application data folder is writable.")
            messagebox.showinfo("Permissions OK", f"Writable:\n{DATA_DIR}")
        except OSError as exc:
            self.set_status(f"Permission test failed: {exc}", self.RED)
            messagebox.showerror(
                "Permission test failed",
                f"Windows error: {getattr(exc, 'winerror', None)}\n{exc}\n\n"
                "Check folder permissions or Windows Security Controlled Folder Access."
            )

    # ---- File & Password Actions ------------------------------------------
    def refresh_capacity_forecast(self):
        if not hasattr(self, "capacity_lbl"):
            return
        info = estimate_card_capacity(self.payload_entry.get(), self.selected_files)
        flow = info["flow"]
        status_color = self.GREEN if info["pct_used"] < 75 else (self.AMBER if info["fits"] else self.RED)
        fit_txt = "Fits PNG card" if info["fits"] else "Exceeds PNG card capacity"
        self.capacity_lbl.config(
            text=(
                f"Water-Data Reservoir: ~{info['estimated_bytes']:,} / {info['capacity_bytes']:,} bytes "
                f"({info['pct_used']}% LSB fill • {flow['regime']} • headroom {flow['headroom_bytes']:,} B) • {fit_txt}"
            ),
            fg=status_color
        )

    def add_files(self):
        paths = filedialog.askopenfilenames(
            title="Attach small files",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")]
        )
        for path in paths:
            if path not in self.selected_files:
                self.selected_files.append(path)
        self.file_count.config(text=f"{len(self.selected_files)} file(s) selected")
        self.refresh_capacity_forecast()

    def clear_files(self):
        self.selected_files.clear()
        self.file_count.config(text="No files selected")
        self.refresh_capacity_forecast()

    def update_password_preview(self, *_):
        if not self.generated_password_value:
            return
        if self.show_full_password.get():
            display_value = self.generated_password_value
        else:
            try:
                visible = int(self.visible_chars.get())
            except (ValueError, tk.TclError):
                visible = 10
            display_value = make_masked_preview(self.generated_password_value, visible)
        self.generated_password.delete(0, tk.END)
        self.generated_password.insert(0, display_value)

    def make_password(self):
        try:
            length = int(self.password_length.get())
            pwd = secure_random_password(
                length,
                symbols=self.symbols_var.get(),
                exclude_ambiguous=self.exclude_ambiguous_var.get()
            )
            if self.multilingual_var.get():
                pwd = apply_mixed_scripts(pwd)
            self.generated_password_value = pwd
            self.show_full_password.set(False)
            self.update_password_preview()
            mode = "mixed-script" if self.multilingual_var.get() else "standard"
            self.set_status(
                f"{length}-character {mode} password generated. "
                "The preview is partially masked."
            )
        except Exception as exc:
            messagebox.showerror("Password error", str(exc))

    def copy_generated(self):
        value = self.generated_password_value
        if value:
            self.copy_secret_with_autoclean(value, label="Generated password")
        else:
            messagebox.showinfo("No password", "Generate a password first.")

    # ---- Security Lab Actions ---------------------------------------------
    def run_word_passphrase(self):
        try:
            phrase = generate_passphrase_words(
                word_count=int(self.phrase_words_var.get()),
                separator=self.phrase_sep_var.get(),
                capitalize=self.phrase_cap_var.get(),
                add_number=self.phrase_num_var.get()
            )
            if self.lab_mixed_scripts_var.get():
                phrase = apply_mixed_scripts(phrase)
            self.lab_password_entry.delete(0, tk.END)
            self.lab_password_entry.insert(0, phrase)
            self._render_analysis(analyze_password(phrase))
            self.set_status(f"Word passphrase ({len(phrase)} chars) generated and analyzed.")
        except Exception as exc:
            messagebox.showerror("Passphrase error", str(exc))

    def run_adaptive_generation(self):
        try:
            length = int(self.lab_length.get())
            pwd = generate_adaptive_password(
                length=length,
                symbols=self.lab_symbols_var.get(),
                base_words=self.base_words_entry.get(),
                use_mixed_scripts=self.lab_mixed_scripts_var.get(),
                padding_mode=self.padding_mode_var.get(),
                exclude_ambiguous=self.lab_exclude_ambig_var.get()
            )
            self.lab_password_entry.delete(0, tk.END)
            self.lab_password_entry.insert(0, pwd)
            self._render_analysis(analyze_password(pwd))
            self.set_status(f"Adaptive password ({len(pwd)} chars) generated and analyzed.")
        except Exception as exc:
            messagebox.showerror("Adaptive generation error", str(exc))

    def run_password_analysis(self):
        candidate = self.lab_password_entry.get()
        report = analyze_password(candidate)
        self._render_analysis(report)
        self.set_status(f"Password intelligence complete: {report['rating']} ({report['score']}/100).")

    def _render_analysis(self, report):
        color = self.GREEN if report["score"] >= 68 else (self.AMBER if report["score"] >= 45 else self.RED)
        self.intel_summary.config(
            text=(
                f"Rating: {report['rating']} ({report['score']}/100)  |  "
                f"Est. Entropy: {report['entropy_bits']} bits  |  "
                f"Length: {report['length']}  |  "
                f"Repetition: {report['repetition_pct']}% (max run: {report['longest_run']})"
            ),
            fg=color
        )
        preds = report.get("predictions", {})
        swarm = report.get("swarm", {})
        lines = ["REASONING CHAIN:"]
        for step in report.get("reasoning_steps", []):
            lines.append(f"  {step}")
        lines.append("")
        lines.append(
            f"PARALLAX SWARM ENSEMBLE (Consensus: {swarm.get('consensus_score', '—')}/100 • "
            f"{swarm.get('confidence', '—')}):"
        )
        for note in swarm.get("swarm_notes", []):
            lines.append(f"  • {note}")
        lines.append(f"  • Best Guess: {swarm.get('best_guess', '—')}")
        lines.append("")
        lines.append("PREDICTIVE ESTIMATES:")
        lines.append(f"  • Online throttled (10/s): {preds.get('online_throttled', '—')}")
        lines.append(f"  • Offline fast GPU (10B/s): {preds.get('offline_fast_gpu', '—')}")
        lines.append(f"  • If +4 chars added: {preds.get('if_plus_4_chars', '—')}")
        lines.append("")
        lines.append("PATTERNS & REPETITION:")
        for p in report["patterns"]:
            lines.append(f"  • {p}")
        lines.append("")
        lines.append("RECOMMENDATIONS:")
        for r in report["recommendations"]:
            lines.append(f"  • {r}")

        self.intel_output.delete("1.0", tk.END)
        self.intel_output.insert(tk.END, "\n".join(lines))

    def copy_lab_password(self):
        val = self.lab_password_entry.get()
        if not val:
            messagebox.showinfo("Nothing to copy", "Enter or generate a password first.")
            return
        self.copy_secret_with_autoclean(val, label="Lab password")

    def clear_clipboard_manual(self):
        try:
            self.root.clipboard_clear()
            self.root.update()
            self._last_copied_secret = None
            self.set_status("Clipboard cleared.")
        except tk.TclError as exc:
            messagebox.showerror("Clipboard error", str(exc))

    def run_batch_generation(self):
        try:
            count = int(self.batch_count_var.get())
            if count < 1 or count > 100:
                raise ValueError("Batch count must be between 1 and 100.")
            length = int(self.lab_length.get())
            items = []
            for _ in range(count):
                pwd = generate_adaptive_password(
                    length=length,
                    symbols=self.lab_symbols_var.get(),
                    base_words=self.base_words_entry.get(),
                    use_mixed_scripts=self.lab_mixed_scripts_var.get(),
                    padding_mode=self.padding_mode_var.get(),
                    exclude_ambiguous=self.lab_exclude_ambig_var.get()
                )
                items.append(pwd)
            self.batch_passwords = items
            self.batch_output.delete("1.0", tk.END)
            formatted = "\n".join(f"{idx + 1:03d}: {pw}" for idx, pw in enumerate(items))
            self.batch_output.insert(tk.END, formatted)
            log.info("Generated batch of %d passwords", count)
            self.set_status(f"Generated {count} independent passwords.")
        except Exception as exc:
            messagebox.showerror("Batch generation error", str(exc))

    def export_batch(self, fmt):
        if not self.batch_passwords:
            messagebox.showwarning("No batch", "Generate a batch of passwords first.")
            return
        default_name = f"StegoVault_Batch_{datetime.datetime.now():%Y%m%d_%H%M%S}.{fmt}"
        filetypes = [("Text file", "*.txt")] if fmt == "txt" else [("CSV file", "*.csv")]
        path = filedialog.asksaveasfilename(
            title="Export generated passwords",
            initialdir=str(DATA_DIR),
            initialfile=default_name,
            defaultextension=f".{fmt}",
            filetypes=filetypes
        )
        if not path:
            return
        try:
            if fmt == "txt":
                Path(path).write_text("\n".join(self.batch_passwords) + "\n", encoding="utf-8")
            else:
                with open(path, "w", newline="", encoding="utf-8") as fh:
                    writer = csv.writer(fh)
                    writer.writerow(["index", "length", "password"])
                    for idx, pw in enumerate(self.batch_passwords, start=1):
                        writer.writerow([idx, len(pw), pw])
            log.info("Exported %d batch passwords to %s", len(self.batch_passwords), Path(path).name)
            self.set_status(f"Exported {len(self.batch_passwords)} passwords to {Path(path).name}.")
            messagebox.showinfo(
                "Batch exported",
                f"Saved {len(self.batch_passwords)} passwords to:\n{path}\n\n"
                "Reminder: Exported files contain sensitive secrets; protect or delete them after use."
            )
        except Exception as exc:
            messagebox.showerror("Export failed", str(exc))

    # ---- Vault Create / Unlock / Audit Actions ----------------------------
    def create_vault(self):
        passphrase = self.master_entry.get()
        confirm = self.confirm_entry.get()
        if len(passphrase) < 10:
            messagebox.showerror("Passphrase required", "Use at least 10 characters.")
            return
        if passphrase != confirm:
            messagebox.showerror("Passphrase mismatch", "The passphrases do not match.")
            return
        payload = {
            "version": APP_VERSION,
            "state_mode": self.altered_state_var.get(),
            "created_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "text": self.payload_entry.get(),
            "hardware_lock": bool(self.hardware_lock_var.get()),
            "hardware_signature": self.hardware_signature() if self.hardware_lock_var.get() else "",
            "attachments": []
        }
        try:
            total = 0
            for path in self.selected_files:
                p = Path(path)
                size = p.stat().st_size
                total += size
                if total > 60 * 1024:
                    raise ValueError("Attachments exceed the 60 KB total limit for this PNG card format.")
                raw = p.read_bytes()
                payload["attachments"].append({
                    "name": p.name,
                    "data": base64.b64encode(raw).decode("ascii")
                })
            package = encode_package(payload, passphrase)
            default_name = f"StegoVault_{datetime.datetime.now():%Y%m%d_%H%M%S}.png"
            path = filedialog.asksaveasfilename(
                title="Save encrypted vault card",
                initialdir=str(DATA_DIR), initialfile=default_name,
                defaultextension=".png", filetypes=[("PNG image", "*.png")]
            )
            if not path:
                return
            embed_package(package, path)
            log.info("Vault card created: %s", Path(path).name)
            self.qr_input.delete("1.0", tk.END)
            self.qr_input.insert(tk.END, base64.b64encode(package).decode("ascii"))
            self.set_status(f"Vault card created: {Path(path).name}")
            messagebox.showinfo("Vault created", f"Encrypted PNG card saved:\n{path}")
        except Exception as exc:
            log.exception("Vault creation failed")
            messagebox.showerror("Creation failed", str(exc))

    def hardware_signature(self):
        return f"{platform.node()}|{platform.machine()}|{platform.system()}"

    def browse_card(self):
        path = filedialog.askopenfilename(filetypes=[("PNG images", "*.png")])
        if path:
            self.card_path.delete(0, tk.END)
            self.card_path.insert(0, path)

    def audit_selected_card(self):
        path = self.card_path.get().strip()
        if not path or not Path(path).is_file():
            messagebox.showerror("Select card", "Choose a valid vault PNG first.")
            return
        try:
            info = audit_vault_card(path)
            flow = info["flow"]
            lines = [
                "=== APEX-SENTINEL & VANTABLACK CARD AUDIT ===",
                f"File: {info['file_name']} ({info['file_bytes']:,} bytes on disk)",
                f"Image: {info['dimensions']} • format={info['format']} • mode={info['mode']}",
                f"LSB Capacity: {info['capacity_bytes']:,} bytes",
                f"SVP2 Header Present: {info['has_svp2_magic']} • Header Valid: {info['header_valid']}",
                f"Embedded Payload Length: {info['payload_len']:,} bytes",
                f"Water-Data Reservoir: {flow['fill_pct']}% full ({flow['regime']}) • headroom {flow['headroom_bytes']:,} B",
            ]
            self.dec_output.delete("1.0", tk.END)
            self.dec_output.insert(tk.END, "\n".join(lines))
            self.set_status(f"Audited {info['file_name']} • SVP2 valid={info['header_valid']}.")
        except Exception as exc:
            messagebox.showerror("Audit failed", str(exc))

    def unlock_card(self):
        path = self.card_path.get().strip()
        passphrase = self.decode_pass.get()
        if not path or not Path(path).is_file():
            messagebox.showerror("Select card", "Choose a valid vault PNG first.")
            return
        if not passphrase:
            messagebox.showerror("Passphrase required", "Enter the master passphrase.")
            return
        try:
            package = extract_package(path)
            payload = decode_package(package, passphrase)
            if payload.get("hardware_lock"):
                expected = payload.get("hardware_signature", "")
                if expected and expected != self.hardware_signature():
                    raise ValueError("This vault is restricted to its originating machine.")
            lines = [
                "=== VAULT DECRYPTED SUCCESSFULLY ===",
                f"Created: {payload.get('created_utc', 'Unknown')}",
                f"State Mode: {payload.get('state_mode', 'Baseline Focus')}",
                f"Attachments: {len(payload.get('attachments', []))}",
                "",
                "SECRET NOTE",
                payload.get("text", ""),
                "",
                "ATTACHMENTS"
            ]
            for item in payload.get("attachments", []):
                raw = base64.b64decode(item["data"], validate=True)
                safe_name = Path(item.get("name", "attachment.bin")).name
                out_path = DATA_DIR / f"extracted_{safe_name}"
                if out_path.exists():
                    out_path = DATA_DIR / f"extracted_{secrets.token_hex(4)}_{safe_name}"
                out_path.write_bytes(raw)
                lines.append(f"Saved: {out_path}")
            self.dec_output.delete("1.0", tk.END)
            self.dec_output.insert(tk.END, "\n".join(lines))
            log.info("Vault successfully decrypted: %s", Path(path).name)
            self.set_status("Vault decrypted successfully.")
        except Exception as exc:
            log.warning("Vault unlock failed: %s", type(exc).__name__)
            self.set_status("Unlock failed — check passphrase, card integrity, or hardware lock.", self.RED)
            messagebox.showerror("Unlock failed", str(exc))

    def save_extracted_note(self):
        text = self.dec_output.get("1.0", tk.END).strip()
        if not text:
            messagebox.showwarning("Nothing to save", "There is no decrypted output.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".txt", filetypes=[("Text file", "*.txt")]
        )
        if path:
            Path(path).write_text(text, encoding="utf-8")
            self.set_status("Decrypted output saved.")

    # ---- QR & Webcam Actions ----------------------------------------------
    def make_qr(self):
        data = self.qr_input.get("1.0", tk.END).strip()
        if not data:
            messagebox.showwarning("QR data missing", "Enter data to encode.")
            return
        try:
            qr = qrcode.QRCode(
                version=None, error_correction=qrcode.constants.ERROR_CORRECT_M,
                box_size=6, border=3
            )
            qr.add_data(data)
            qr.make(fit=True)
            self.current_qr = qr.make_image(fill_color="black", back_color="white").convert("RGB")
            preview = self.current_qr.copy()
            preview.thumbnail((300, 300))
            self.qr_photo = ImageTk.PhotoImage(preview)
            self.qr_preview.config(image=self.qr_photo, text="", width=300, height=300)
            self.set_status("QR code generated.")
        except Exception as exc:
            messagebox.showerror("QR error", str(exc))

    def save_qr(self):
        if self.current_qr is None:
            messagebox.showwarning("No QR code", "Generate a QR code first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".png", filetypes=[("PNG image", "*.png")]
        )
        if path:
            self.current_qr.save(path)
            self.set_status(f"QR image saved: {Path(path).name}")

    def load_qr_text(self):
        path = filedialog.askopenfilename(filetypes=[("Text files", "*.txt"), ("All files", "*.*")])
        if path:
            raw = Path(path).read_text(encoding="utf-8")
            self.qr_input.delete("1.0", tk.END)
            self.qr_input.insert(tk.END, raw)

    def toggle_camera(self):
        if not self.camera_enabled.get():
            self.stop_camera()
            return
        if cv2 is None:
            self.camera_enabled.set(False)
            messagebox.showerror(
                "OpenCV unavailable",
                f"Install webcam support with:\n{sys.executable} -m pip install --user opencv-python"
            )
            return
        self.camera_status.config(text="Camera enabled — it opens only when you start a scan.")
        self.set_status("Webcam permission enabled.")

    def scan_webcam(self):
        if not self.camera_enabled.get():
            messagebox.showwarning("Camera is off", "Enable webcam access first.")
            return
        if cv2 is None:
            messagebox.showerror("Webcam unavailable", "OpenCV is not installed.")
            return
        cap = None
        win_title = "Stego-Vault QR Scanner — ESC to cancel"
        try:
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW if os.name == "nt" else 0)
            if not cap.isOpened():
                raise RuntimeError("Windows could not open the webcam.")
            detector = cv2.QRCodeDetector()
            self.camera_status.config(text="Scanning — press ESC or close window to cancel.")
            while True:
                ok, frame = cap.read()
                if not ok:
                    raise RuntimeError("Could not read a frame from the webcam.")
                data, points, _ = detector.detectAndDecode(frame)
                if points is not None:
                    cv2.polylines(frame, [points.astype(int)], True, (0, 220, 100), 2)
                cv2.imshow(win_title, frame)
                key = cv2.waitKey(1) & 0xFF
                if data:
                    self.qr_input.delete("1.0", tk.END)
                    self.qr_input.insert(tk.END, data)
                    self.set_status("QR content captured.")
                    break
                if key == 27:
                    break
                try:
                    if cv2.getWindowProperty(win_title, cv2.WND_PROP_VISIBLE) < 1:
                        break
                except Exception:
                    pass
        except Exception as exc:
            messagebox.showerror("Webcam scan error", str(exc))
        finally:
            if cap is not None:
                cap.release()
            try:
                cv2.destroyAllWindows()
            except Exception:
                pass
            self.camera_status.config(text="Camera enabled." if self.camera_enabled.get() else "Camera is off")

    def stop_camera(self):
        self.camera_status.config(text="Camera is off")
        self.set_status("Webcam access disabled.")

    def on_close(self):
        save_settings({
            "altered_state": str(self.altered_state_var.get()),
            "multilingual": bool(self.multilingual_var.get()),
            "exclude_ambiguous": bool(self.exclude_ambiguous_var.get()),
            "lab_mixed_scripts": bool(self.lab_mixed_scripts_var.get()),
            "lab_symbols": bool(self.lab_symbols_var.get()),
            "lab_exclude_ambig": bool(self.lab_exclude_ambig_var.get()),
            "phrase_words": int(self.phrase_words_var.get()),
            "phrase_sep": str(self.phrase_sep_var.get() or "-"),
            "phrase_cap": bool(self.phrase_cap_var.get()),
            "phrase_num": bool(self.phrase_num_var.get()),
            "clipboard_autoclean": bool(self.clipboard_autoclean_var.get()),
            "clipboard_clear_seconds": int(self.clipboard_clear_seconds.get()),
            "symbols": bool(self.symbols_var.get()),
            "hardware_lock": bool(self.hardware_lock_var.get()),
        })
        self.bridge.stop()
        if self._clipboard_after_id is not None:
            try:
                self.root.after_cancel(self._clipboard_after_id)
            except Exception:
                pass
            self._clipboard_after_id = None
        self.camera_enabled.set(False)
        self.stop_camera()
        log.info("Application closed")
        self.root.destroy()


# ---- Cadence-Seal (Rhythmic Inter-Tap & Harmonic Digest) ---------------
CADENCE_INTERVALS = [
    (0.55, "Unison / Rapid Double-Tap", "·"),
    (0.85, "Minor Second / Crisp Pulse", "··"),
    (1.15, "Major Second / Steady Beat", "-"),
    (1.50, "Perfect Fourth / Syncopated Lift", "-·"),
    (2.00, "Perfect Fifth / Long Hold", "—"),
    (99.0, "Wide Pause / Phrase Break", "— ·"),
]


def classify_tap_ratios(timestamps):
    """Convert raw tap timestamps (seconds) into normalized interval labels & cadence glyphs."""
    if len(timestamps) < 2:
        return []
    deltas = [max(0.01, timestamps[i] - timestamps[i - 1]) for i in range(1, len(timestamps))]
    median_dt = sorted(deltas)[len(deltas) // 2]
    results = []
    for dt in deltas:
        ratio = dt / max(0.01, median_dt)
        chosen_label, chosen_glyph = CADENCE_INTERVALS[-1][1], CADENCE_INTERVALS[-1][2]
        for threshold, label, glyph in CADENCE_INTERVALS:
            if ratio <= threshold:
                chosen_label, chosen_glyph = label, glyph
                break
        bucket_ms = int(round((dt * 1000.0) / 50.0) * 50)
        results.append({
            "ms": bucket_ms,
            "ratio": round(ratio, 2),
            "label": chosen_label,
            "glyph": chosen_glyph,
        })
    return results


def compute_cadence_seal(steps, salt_tag="SVP2-CADENCE"):
    """Derive a deterministic SHA-256 cadence digest from classified tap steps."""
    if not steps:
        return ""
    canonical = "|".join(f"{s['ms']}:{s['glyph']}" for s in steps)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(f"{salt_tag}::{canonical}".encode("utf-8"))
    raw_hex = digest.finalize().hex().upper()
    return "-".join(raw_hex[i:i + 6] for i in range(0, 24, 6))


class CadenceSealTab:
    """Self-contained tab attached to StegoVaultApp without modifying existing code."""

    def __init__(self, app):
        self.app = app
        self.taps = []
        self.steps = []
        self.seal_value = ""

        self.tab = tk.Frame(app.notebook, bg=app.BG)
        app.notebook.add(self.tab, text="  CADENCE SEAL  ")

        ctrl = app.panel(self.tab, "RHYTHMIC TAP CAPTURE (SPACEBAR OR BUTTON)")
        tk.Label(
            ctrl,
            text="Tap a personal rhythm (at least 3 taps / 2 intervals). Relative timing ratios are "
                 "quantized into 50 ms buckets—no raw timestamps or audio are recorded.",
            bg=app.PANEL, fg=app.MUTED, wraplength=900, justify="left"
        ).pack(anchor="w", pady=(0, 8))

        btn_row = tk.Frame(ctrl, bg=app.PANEL)
        btn_row.pack(fill="x")
        self.tap_btn = app.button(btn_row, "🥁 TAP BEAT (Space)", self.record_tap, primary=True)
        self.tap_btn.pack(side="left")
        self.tap_btn.bind("<space>", self._on_space_tap)
        app.button(btn_row, "Reset Rhythm", self.reset_rhythm).pack(side="left", padx=8)
        app.button(btn_row, "Copy Cadence Seal", self.copy_seal).pack(side="left")

        self.wave_canvas = tk.Canvas(
            ctrl, height=110, bg=app.PANEL2, highlightthickness=0
        )
        self.wave_canvas.pack(fill="x", pady=(10, 4))

        out_panel = app.panel(self.tab, "HARMONIC CADENCE & SEAL DIGEST")
        self.seal_lbl = tk.Label(
            out_panel, text="Cadence Seal: —  |  Taps: 0",
            bg=app.PANEL, fg=app.BLUE, font=("Consolas", 10, "bold")
        )
        self.seal_lbl.pack(anchor="w", pady=(0, 6))

        self.detail_box = tk.Text(
            out_panel, height=10, bg=app.PANEL2, fg=app.TEXT,
            insertbackground=app.TEXT, relief="flat", wrap="word", font=("Consolas", 9)
        )
        self.detail_box.pack(fill="both", expand=True)

    def _on_space_tap(self, _event):
        self.record_tap()
        return "break"

    def record_tap(self):
        now = time.monotonic()
        if self.taps and (now - self.taps[-1]) > 4.0:
            self.taps = [now]
            self.steps = []
            self.seal_value = ""
            self.app.set_status("Started new rhythm sequence after >4s pause.")
        else:
            self.taps.append(now)
            self.steps = classify_tap_ratios(self.taps)
            self.seal_value = compute_cadence_seal(self.steps)
            self.app.set_status(f"Cadence tap #{len(self.taps)} recorded ({len(self.steps)} intervals).")
        self._refresh_view()

    def reset_rhythm(self):
        self.taps.clear()
        self.steps.clear()
        self.seal_value = ""
        self._refresh_view()
        self.app.set_status("Cadence rhythm cleared.")

    def copy_seal(self):
        if not self.seal_value:
            messagebox.showinfo("No Cadence Seal", "Tap a rhythm with at least 2 intervals first.")
            return
        self.app.copy_secret_with_autoclean(self.seal_value, label="Cadence Seal")

    def _refresh_view(self):
        self.wave_canvas.delete("all")
        w = max(300, self.wave_canvas.winfo_width() or 860)
        h = 110
        mid_y = h // 2
        self.wave_canvas.create_line(16, mid_y, w - 16, mid_y, fill=self.app.PANEL, dash=(4, 4))

        if self.steps:
            step_w = max(24, min(70, (w - 40) // max(1, len(self.steps))))
            x = 24
            for st in self.steps:
                amp = max(12, min(42, int(st["ratio"] * 22)))
                self.wave_canvas.create_rectangle(
                    x, mid_y - amp, x + step_w - 8, mid_y + amp,
                    fill=self.app.BLUE, outline=""
                )
                self.wave_canvas.create_text(
                    x + (step_w - 8) // 2, h - 14,
                    text=st["glyph"], fill=self.app.GREEN, font=("Consolas", 9, "bold")
                )
                x += step_w

        seal_txt = self.seal_value or "—"
        self.seal_lbl.config(
            text=f"Cadence Seal: {seal_txt}  |  Taps: {len(self.taps)}  |  Intervals: {len(self.steps)}"
        )
        lines = []
        for idx, st in enumerate(self.steps, start=1):
            lines.append(
                f"Interval {idx:02d}: ~{st['ms']:4d} ms (ratio {st['ratio']:.2f}x) -> "
                f"{st['glyph']}  [{st['label']}]"
            )
        self.detail_box.delete("1.0", tk.END)
        self.detail_box.insert("1.0", "\n".join(lines) if lines else "Tap at least twice to inspect interval ratios.")


def main():
    root = tk.Tk()
    app = StegoVaultApp(root)
    CadenceSealTab(app)
    root.mainloop()

if __name__ == "__main__":
    main()