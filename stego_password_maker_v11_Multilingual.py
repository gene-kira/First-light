"""
STEGO-VAULT PRO — Secure Studio Edition
Windows-friendly encrypted payload vault with PNG LSB cards and QR transfer.

Security notes:
- The master passphrase is never saved in plaintext.
- Webcam face detection is NOT used as authentication.
- Administrator privileges are optional; data is stored under the user's
  writable application-data directory.
- PNG cards are lossless containers. Do not resize/recompress them.
"""

import os
import sys
import json
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
APP_VERSION = "2.1"
MAGIC = b"SVP2"
SALT_SIZE = 16
KDF_ITERATIONS = 600_000
HEADER = MAGIC + struct.pack(">I", 0)  # replaced with actual encrypted length
DEFAULT_CARD_SIZE = (1200, 800)
MAX_IMPORT_BYTES = 20 * 1024 * 1024

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
        alphabet += "!@#$%^&*()-_=+[]{}:,.?"
    if length < 8 or length > 256:
        raise ValueError("Password length must be between 8 and 256.")
    # Ensure a useful mix, then cryptographically shuffle.
    required = [
        secrets.choice(string.ascii_lowercase),
        secrets.choice(string.ascii_uppercase),
        secrets.choice(string.digits)
    ]
    if symbols:
        required.append(secrets.choice("!@#$%^&*()-_=+[]{}:,.?"))
    required.extend(secrets.choice(alphabet) for _ in range(length - len(required)))
    secrets.SystemRandom().shuffle(required)
    return "".join(required)


# Approximate letter-to-letter transliteration maps for mixed-script passwords.
# These are Unicode characters, not translations of whole words.
MULTI_SCRIPT_MAPS = {
    "Greek": {
        "a":"α","b":"β","c":"κ","d":"δ","e":"ε","f":"φ","g":"γ","h":"η",
        "i":"ι","j":"ξ","k":"κ","l":"λ","m":"μ","n":"ν","o":"ο","p":"ρ",
        "q":"θ","r":"ρ","s":"σ","t":"τ","u":"υ","v":"ν","w":"ω","x":"χ",
        "y":"ψ","z":"ζ"
    },
    "Cyrillic": {
        "a":"а","b":"б","c":"с","d":"д","e":"е","f":"ф","g":"г","h":"н",
        "i":"і","j":"ј","k":"к","l":"л","m":"м","n":"п","o":"о","p":"р",
        "q":"я","r":"г","s":"ѕ","t":"т","u":"ц","v":"в","w":"ш","x":"х",
        "y":"у","z":"з"
    },
    "Armenian": {
        "a":"ա","b":"բ","c":"ց","d":"դ","e":"ե","f":"ֆ","g":"գ","h":"հ",
        "i":"ի","j":"ջ","k":"կ","l":"լ","m":"մ","n":"ն","o":"ո","p":"պ",
        "q":"ք","r":"ր","s":"ս","t":"տ","u":"ու","v":"վ","w":"ւ","x":"խ",
        "y":"յ","z":"զ"
    },
    "Ukrainian": {
        "a":"а","b":"б","c":"ц","d":"д","e":"е","f":"ф","g":"ґ","h":"г",
        "i":"і","j":"й","k":"к","l":"л","m":"м","n":"н","o":"о","p":"п",
        "q":"к","r":"р","s":"с","t":"т","u":"у","v":"в","w":"ш","x":"х",
        "y":"и","z":"з"
    }
}

def detect_system_language():
    """Return a display label for the OS locale; generator remains ASCII by default."""
    try:
        import locale
        lang = (locale.getlocale()[0] or "").lower()
        if lang.startswith(("el",)): return "Greek"
        if lang.startswith(("ru", "bg", "sr")): return "Cyrillic"
        if lang.startswith(("hy",)): return "Armenian"
        if lang.startswith(("uk",)): return "Ukrainian"
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
    # RGB PNG: one payload bit in the least significant bit of each red channel.
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
        # Read fixed header first, then the exact declared payload.
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

    def __init__(self, root):
        self.root = root
        self.root.title(f"Stego-Vault Pro {APP_VERSION} — Secure Studio")
        self.root.geometry("1000x760")
        self.root.minsize(780, 600)
        self.root.configure(bg=self.BG)
        self.selected_files = []
        self.generated_password_value = ""
        self.show_full_password = tk.BooleanVar(value=False)
        self.multilingual_var = tk.BooleanVar(value=False)
        self.current_qr = None
        self.qr_photo = None
        self.camera_enabled = tk.BooleanVar(value=False)
        self.symbols_var = tk.BooleanVar(value=True)
        self.hardware_lock_var = tk.BooleanVar(value=False)
        self._camera = None
        self._camera_window = False
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
            padding=(15, 10), font=("Segoe UI", 9, "bold")
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
        tk.Label(header, text="SECURE STUDIO  •  ENCRYPT  •  EMBED  •  RECOVER  •  TRANSFER",
                 bg=self.BG, fg=self.BLUE, font=("Segoe UI", 9, "bold")).pack(anchor="w", pady=(3, 0))

        self.notebook = ttk.Notebook(self.root)
        self.notebook.pack(fill="both", expand=True, padx=20, pady=8)
        self.gen_tab = tk.Frame(self.notebook, bg=self.BG)
        self.dec_tab = tk.Frame(self.notebook, bg=self.BG)
        self.qr_tab = tk.Frame(self.notebook, bg=self.BG)
        self.settings_tab = tk.Frame(self.notebook, bg=self.BG)
        self.notebook.add(self.gen_tab, text="  CREATE VAULT  ")
        self.notebook.add(self.dec_tab, text="  UNLOCK / EXTRACT  ")
        self.notebook.add(self.qr_tab, text="  QR TRANSFER  ")
        self.notebook.add(self.settings_tab, text="  SETTINGS / DIAGNOSTICS  ")
        self._build_generator()
        self._build_decoder()
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
        frame.pack(fill="x", padx=18, pady=9)
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

        p = self.panel(self.gen_tab, "PASSWORD GENERATOR")
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
        # Multilingual mode is OFF by default: standard ASCII is the safest
        # compatibility choice for ordinary websites and services.
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
            bg=self.PANEL, fg=self.MUTED, wraplength=820, justify="left"
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
            bg=self.PANEL, fg=self.MUTED, wraplength=820, justify="left"
        ).pack(anchor="w", pady=(0, 5))

        row2 = tk.Frame(p, bg=self.PANEL)
        row2.pack(fill="x")
        self.button(row2, "Generate password", self.make_password).pack(side="left")
        self.button(row2, "Copy FULL password", self.copy_generated).pack(side="left", padx=7)

        self.button(self.gen_tab, "🔒 ENCRYPT & CREATE PNG VAULT CARD",
                    self.create_vault, primary=True).pack(fill="x", padx=18, pady=12)

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

    def _build_settings(self):
        f = self.panel(self.settings_tab, "APPLICATION STATUS")
        self.admin_label = tk.Label(f, text="", bg=self.PANEL, fg=self.GREEN,
                                    font=("Segoe UI", 10, "bold"))
        self.admin_label.pack(anchor="w", pady=4)
        tk.Label(f, text=f"Data directory: {DATA_DIR}",
                 bg=self.PANEL, fg=self.TEXT, wraplength=850,
                 justify="left").pack(anchor="w", pady=4)
        tk.Label(f, text=f"Audit log: {LOG_PATH}",
                 bg=self.PANEL, fg=self.MUTED, wraplength=850,
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
                 bg=self.PANEL, fg=self.MUTED, wraplength=850,
                 justify="left").pack(anchor="w", pady=8)

        g = self.panel(self.settings_tab, "SECURITY & COMPATIBILITY")
        notes = [
            "Encryption: Fernet authenticated encryption with PBKDF2-HMAC-SHA256.",
            f"Key derivation: {KDF_ITERATIONS:,} iterations per unlock.",
            "Card format: PNG least-significant-bit payload; keep the original PNG unchanged.",
            "No plaintext passphrase is saved. There is no silent auto-unlock.",
            "Hardware lock is a portability restriction, not a substitute for encryption.",
            "Webcam face detection is not identity verification and is not used to unlock vaults.",
            "Password generator supports optional Greek, Cyrillic, Armenian, and Ukrainian mixed-script characters.",
            "Password preview can mask all but a configurable number of characters; copying always copies the full password.",
            "Mixed-script passwords can be rejected by websites and can be difficult to type; keep a secure copy."
        ]
        for item in notes:
            tk.Label(g, text="• " + item, bg=self.PANEL, fg=self.TEXT,
                     wraplength=850, justify="left").pack(anchor="w", pady=3)

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
            self.root.clipboard_clear()
            self.root.clipboard_append(value)
            self.set_status(
                "Complete password copied to clipboard. "
                "Remember to clear the clipboard after use."
            )
        else:
            messagebox.showinfo("No password", "Generate a password first.")

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
                # Avoid overwriting an existing extraction.
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
        # Scanner opens the camera only during an explicit scan; disabling prevents new scans.
        self.camera_status.config(text="Camera is off")
        self.set_status("Webcam access disabled.")

    def on_close(self):
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
