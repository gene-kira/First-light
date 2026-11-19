"""
STEGO-VAULT PRO — Secure Studio Edition
Windows-friendly encrypted payload vault with PNG LSB cards, QR transfer,
and a local Security Lab for password intelligence, adaptive generation,
batch export, and self-cleaning clipboard handling.

Security notes:
- The master passphrase is never saved in plaintext.
- Webcam face detection is NOT used as authentication.
- Administrator privileges are optional; data is stored under the user's
  writable application-data directory.
- PNG cards are lossless containers. Do not resize/recompress them.
"""

import os
import re
import csv
import sys
import json
import math
import base64
import secrets
import string
import struct
import logging
import subprocess
import ctypes
import platform
import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, filedialog

# ---- Dependency bootstrap (user-level; no admin required) -----------------
def ensure_package(import_name, package_name):
    try:
        __import__(import_name)
        return True
    except ImportError:
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
APP_VERSION = "2.2"
MAGIC = b"SVP2"
SALT_SIZE = 16
KDF_ITERATIONS = 600_000
HEADER = MAGIC + struct.pack(">I", 0)  # replaced with actual encrypted length
DEFAULT_CARD_SIZE = (1200, 800)
MAX_IMPORT_BYTES = 20 * 1024 * 1024
SYMBOL_SET = "!@#$%^&*()-_=+[]{}:,.?"

def app_data_dir():
    base = os.environ.get("LOCALAPPDATA") or str(Path.home() / ".local" / "share")
    path = Path(base) / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path

DATA_DIR = app_data_dir()
LOG_PATH = DATA_DIR / "vault_audit.log"
SETTINGS_PATH = DATA_DIR / "settings.json"

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

def secure_random_password(length, symbols=True):
    alphabet = string.ascii_letters + string.digits
    if symbols:
        alphabet += SYMBOL_SET
    if length < 8 or length > 256:
        raise ValueError("Password length must be between 8 and 256.")
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits)
    ]
    if symbols:
        required.append(secrets.choice(SYMBOL_SET))
    required.extend(secrets.choice(alphabet) for _ in range(length - len(required)))
    secrets.SystemRandom().shuffle(required)
    return "".join(required)


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
                               use_mixed_scripts=False, padding_mode="balanced"):
    """Generate an adaptive password combining optional base words and cryptographic padding."""
    if length < 8 or length > 256:
        raise ValueError("Password length must be between 8 and 256.")

    raw_words = [w.strip() for w in re.split(r"[,;\s]+", base_words or "") if w.strip()]
    stylized_words = [_stylize_word(w) for w in raw_words]
    stylized_words = [w for w in stylized_words if w]

    pad_alphabet = string.ascii_letters + string.digits + (SYMBOL_SET if symbols else "")
    separator = secrets.choice(SYMBOL_SET if symbols else "-_.")

    # Padding mode controls how strongly random noise separates/extends base words.
    pad_ratios = {"minimal": 0.25, "balanced": 0.55, "heavy": 0.85}
    ratio = pad_ratios.get(padding_mode, 0.55)

    if not stylized_words:
        pwd = secure_random_password(length, symbols=symbols)
    else:
        pieces = []
        for idx, word in enumerate(stylized_words):
            pieces.append(word)
            if idx < len(stylized_words) - 1:
                pieces.append(separator)

        joined = "".join(pieces)
        target_pad_len = max(4, int(length * ratio)) if len(joined) < length else 2
        pad_chars = [secrets.choice(pad_alphabet) for _ in range(target_pad_len)]
        if symbols and not any(c in SYMBOL_SET for c in joined + "".join(pad_chars)):
            pad_chars[0] = secrets.choice(SYMBOL_SET)
        if not any(c.isdigit() for c in joined + "".join(pad_chars)):
            pad_chars[-1] = secrets.choice(string.digits)

        # Interleave or append padding depending on mode.
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

def analyze_password(password):
    """Perform local strength estimation, pattern detection, and repetition analysis."""
    if not password:
        return {
            "score": 0,
            "rating": "Empty",
            "entropy_bits": 0.0,
            "length": 0,
            "unique_chars": 0,
            "repetition_pct": 0.0,
            "longest_run": 0,
            "patterns": ["No password provided."],
            "recommendations": ["Enter or generate a password with at least 12–16 characters."]
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

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_ascii_sym:
        pool_size += len(SYMBOL_SET)
    if has_non_ascii:
        pool_size += 64  # conservative estimate for mixed non-ASCII scripts

    pool_size = max(pool_size, unique_chars, 1)
    raw_entropy = length * math.log2(pool_size)

    patterns = []
    penalty = 0.0

    if longest_run >= 3:
        patterns.append(f"Repeated character run detected (up to {longest_run}x in a row).")
        penalty += min(18.0, (longest_run - 2) * 5.0)

    if repetition_pct >= 35.0:
        patterns.append(f"High character repetition ({repetition_pct}% of characters repeat).")
        penalty += min(20.0, (repetition_pct - 30.0) * 0.6)

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
        patterns.append("Sequential or keyboard-walk pattern detected (4+ consecutive chars).")
        penalty += 15.0

    # Repeated multi-character substrings (length >= 3)
    repeated_subs = set()
    for size in range(3, min(8, length // 2 + 1)):
        for start in range(length - size + 1):
            sub = password[start:start + size]
            if password.count(sub) > 1:
                repeated_subs.add(sub)
    if repeated_subs:
        sample = ", ".join(sorted(repeated_subs)[:3])
        patterns.append(f"Repeated substring pattern ({sample}).")
        penalty += min(15.0, len(repeated_subs) * 5.0)

    if re.search(r"(19\d\d|20\d\d|1234|admin|password|qwerty|letmein|welcome)", lower_pwd):
        patterns.append("Common word, year, or predictable token detected.")
        penalty += 15.0

    if has_non_ascii:
        patterns.append("Non-ASCII / mixed-script Unicode characters present.")

    if not patterns:
        patterns.append("No obvious sequential, dictionary, or heavy repetition patterns found.")

    effective_entropy = max(0.0, raw_entropy * max(0.35, 1.0 - penalty / 100.0))

    # Score 0-100 based on effective entropy and length
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
        "length": length,
        "unique_chars": unique_chars,
        "repetition_pct": repetition_pct,
        "longest_run": longest_run,
        "patterns": patterns,
        "recommendations": recommendations
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
        self.root.geometry("1040x800")
        self.root.minsize(820, 640)
        self.root.configure(bg=self.BG)

        self.selected_files = []
        self.generated_password_value = ""
        self.batch_passwords = []
        self.show_full_password = tk.BooleanVar(value=False)
        self.multilingual_var = tk.BooleanVar(value=False)
        self.lab_mixed_scripts_var = tk.BooleanVar(value=False)
        self.lab_symbols_var = tk.BooleanVar(value=True)
        self.clipboard_autoclean_var = tk.BooleanVar(value=True)
        self.clipboard_clear_seconds = tk.IntVar(value=20)
        self.current_qr = None
        self.qr_photo = None
        self.camera_enabled = tk.BooleanVar(value=False)
        self.symbols_var = tk.BooleanVar(value=True)
        self.hardware_lock_var = tk.BooleanVar(value=False)
        self._camera = None
        self._camera_window = False
        self._clipboard_after_id = None
        self._last_copied_secret = None

        self._build_style()
        self._build_ui()
        self.root.protocol("WM_DELETE_WINDOW", self.on_close)
        self.set_status("Ready • Files are stored in your user profile.")
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
            padding=(14, 10), font=("Segoe UI", 9, "bold")
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
        tk.Label(header, text="SECURE STUDIO  •  ENCRYPT  •  EMBED  •  RECOVER  •  SECURITY LAB  •  TRANSFER",
                 bg=self.BG, fg=self.BLUE, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 0))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=8)
        self.gen_tab = tk.Frame(self.notebook, bg=self.BG)
        self.dec_tab = tk.Frame(self.notebook, bg=self.BG)
        self.lab_tab = tk.Frame(self.notebook, bg=self.BG)
        self.qr_tab = tk.Frame(self.notebook, bg=self.BG)
        self.settings_tab = tk.Frame(self.notebook, bg=self.BG)

        self.notebook.add(self.gen_tab, text="  CREATE VAULT  ")
        self.notebook.add(self.dec_tab, text="  UNLOCK / EXTRACT  ")
        self.notebook.add(self.lab_tab, text="  SECURITY LAB  ")
        self.notebook.add(self.qr_tab, text="  QR TRANSFER  ")
        self.notebook.add(self.settings_tab, text="  SETTINGS / DIAGNOSTICS  ")

        self._build_generator()
        self._build_decoder()
        self._build_security_lab()
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
            bg=self.PANEL, fg=self.MUTED, wraplength=860, justify="left"
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
            bg=self.PANEL, fg=self.MUTED, wraplength=860, justify="left"
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
        self.label(f, "Master passphrase")
        self.decode_pass = self.entry(f, show="•")
        self.button(f, "🔓 DECRYPT & EXTRACT", self.unlock_card, primary=True).pack(
            fill="x", pady=8
        )
        out = self.panel(self.dec_tab, "DECRYPTED CONTENT")
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

        # 1. Adaptive Password Generator
        adapt = self.panel(inner, "ADAPTIVE PASSWORD GENERATOR")
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
                       activebackground=self.PANEL).pack(side="left")

        self.label(adapt, "Optional base words (comma, space, or newline separated)")
        self.base_words_entry = self.entry(adapt)
        self.base_words_entry.insert(0, "")

        self.label(adapt, "Generated adaptive password (also feeds strength analyzer)")
        self.lab_password_entry = self.entry(adapt)

        btn_row = tk.Frame(adapt, bg=self.PANEL)
        btn_row.pack(fill="x", pady=(4, 0))
        self.button(btn_row, "Generate adaptive password", self.run_adaptive_generation, primary=True).pack(side="left")
        self.button(btn_row, "Analyze current text", self.run_password_analysis).pack(side="left", padx=8)
        self.button(btn_row, "Copy with auto-clean", self.copy_lab_password).pack(side="left")

        # 2. Local Password Intelligence
        intel = self.panel(inner, "LOCAL PASSWORD INTELLIGENCE")
        self.intel_summary = tk.Label(
            intel, text="Rating: —  |  Estimated Entropy: —  |  Repetition: —",
            bg=self.PANEL, fg=self.BLUE, font=("Segoe UI", 10, "bold")
        )
        self.intel_summary.pack(anchor="w", pady=(0, 4))
        self.intel_output = tk.Text(intel, height=7, bg=self.PANEL2, fg=self.TEXT,
                                    insertbackground=self.TEXT, relief="flat",
                                    wrap="word", font=("Consolas", 9))
        self.intel_output.pack(fill="both", expand=True)

        # 3. Clipboard Self-Cleaning Controls
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
            bg=self.PANEL, fg=self.MUTED, wraplength=880, justify="left"
        ).pack(anchor="w", pady=(5, 0))

        # 4. Batch Generation (up to 100 passwords)
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

    # ---- Tab 4: QR Transfer -----------------------------------------------
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

    # ---- Tab 5: Settings & Diagnostics ------------------------------------
    def _build_settings(self):
        f = self.panel(self.settings_tab, "APPLICATION STATUS")
        self.admin_label = tk.Label(f, text="", bg=self.PANEL, fg=self.GREEN,
                                    font=("Segoe UI", 10, "bold"))
        self.admin_label.pack(anchor="w", pady=4)
        tk.Label(f, text=f"Data directory: {DATA_DIR}",
                 bg=self.PANEL, fg=self.TEXT, wraplength=880,
                 justify="left").pack(anchor="w", pady=4)
        tk.Label(f, text=f"Audit log: {LOG_PATH}",
                 bg=self.PANEL, fg=self.MUTED, wraplength=880,
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
                 bg=self.PANEL, fg=self.MUTED, wraplength=880,
                 justify="left").pack(anchor="w", pady=8)

        g = self.panel(self.settings_tab, "SECURITY & COMPATIBILITY DIAGNOSTICS")
        notes = [
            "Encryption: Fernet authenticated encryption with PBKDF2-HMAC-SHA256.",
            f"Key derivation: {KDF_ITERATIONS:,} iterations per unlock.",
            "Card format: PNG least-significant-bit payload; keep the original PNG unchanged.",
            "No plaintext passphrase is saved. There is no silent auto-unlock.",
            "Hardware lock is a portability restriction, not a substitute for encryption.",
            "Webcam face detection is not identity verification and is not used to unlock vaults.",
            "Unicode compatibility: Mixed-script or non-ASCII passwords can fail input filters, normalization (NFC/NFD), or keyboard layouts on some websites/apps.",
            "Clipboard history risk: OS clipboard history features (such as Windows Clipboard History) or background apps may retain copied secrets even after active clipboard clearing.",
            "Password storage risk: Exported password batches or unencrypted notes are sensitive secrets—store them in an encrypted vault or protected medium and delete temporary files when finished."
        ]
        for item in notes:
            tk.Label(g, text="• " + item, bg=self.PANEL, fg=self.TEXT,
                     wraplength=880, justify="left").pack(anchor="w", pady=3)

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
    def add_files(self):
        paths = filedialog.askopenfilenames(
            title="Attach small files",
            filetypes=[("Images", "*.png *.jpg *.jpeg *.bmp"), ("All files", "*.*")]
        )
        for path in paths:
            if path not in self.selected_files:
                self.selected_files.append(path)
        self.file_count.config(text=f"{len(self.selected_files)} file(s) selected")

    def clear_files(self):
        self.selected_files.clear()
        self.file_count.config(text="No files selected")

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
            pwd = secure_random_password(length, self.symbols_var.get())
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
    def run_adaptive_generation(self):
        try:
            length = int(self.lab_length.get())
            pwd = generate_adaptive_password(
                length=length,
                symbols=self.lab_symbols_var.get(),
                base_words=self.base_words_entry.get(),
                use_mixed_scripts=self.lab_mixed_scripts_var.get(),
                padding_mode=self.padding_mode_var.get()
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
        lines = ["PATTERNS & REPETITION:"]
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
                    padding_mode=self.padding_mode_var.get()
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

    # ---- Vault Create / Unlock Actions ------------------------------------
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
        try:
            cap = cv2.VideoCapture(0, cv2.CAP_DSHOW if os.name == "nt" else 0)
            if not cap.isOpened():
                raise RuntimeError("Windows could not open the webcam.")
            detector = cv2.QRCodeDetector()
            self.camera_status.config(text="Scanning — press ESC to cancel.")
            while True:
                ok, frame = cap.read()
                if not ok:
                    raise RuntimeError("Could not read a frame from the webcam.")
                data, points, _ = detector.detectAndDecode(frame)
                if points is not None:
                    cv2.polylines(frame, [points.astype(int)], True, (0, 220, 100), 2)
                cv2.imshow("Stego-Vault QR Scanner — ESC to cancel", frame)
                key = cv2.waitKey(1) & 0xFF
                if data:
                    self.qr_input.delete("1.0", tk.END)
                    self.qr_input.insert(tk.END, data)
                    self.set_status("QR content captured.")
                    break
                if key == 27:
                    break
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

def main():
    root = tk.Tk()
    app = StegoVaultApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()