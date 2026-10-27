#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Multimodal AI Encryption — Fixed & Hardened Edition

Core requirements:
    pip install cryptography

Optional features:
    pip install tkinterdnd2       # drag and drop
    pip install sounddevice scipy # record sound/voice samples
    pip install matplotlib        # glyph timeline chart

Important:
- Keep your PIN, phrase, glyph seed, numeric layer, and any selected factor files.
- If you select sound/voice factor files during encryption, select the SAME files
  during decryption. They act as additional secret factors.
- This app does not perform biometric speaker verification. Phrase matching is
  text confirmation; the optional audio files are hashed as extra factors.
- The encrypted package is portable to other PCs; it is not tied to machine ID.
"""

import os
import sys
import json
import base64
import hashlib
import hmac
import secrets
import tempfile
import datetime
import traceback
import threading
from pathlib import Path
from typing import Optional

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

try:
    from cryptography.fernet import Fernet, InvalidToken
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
except ImportError:
    Fernet = None
    InvalidToken = Exception
    PBKDF2HMAC = None

try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
    DND_AVAILABLE = True
except ImportError:
    DND_FILES = None
    TkinterDnD = None
    DND_AVAILABLE = False

try:
    import sounddevice as sd
    from scipy.io.wavfile import write as wav_write
    AUDIO_AVAILABLE = True
except ImportError:
    sd = None
    wav_write = None
    AUDIO_AVAILABLE = False

try:
    import matplotlib
    matplotlib.use("TkAgg")
    import matplotlib.pyplot as plt
    PLOT_AVAILABLE = True
except Exception:
    plt = None
    PLOT_AVAILABLE = False


APP_NAME = "Multimodal AI Encryption"
FORMAT_NAME = "MME-PACKAGE"
FORMAT_VERSION = 2
KDF_ITERATIONS = 600_000
HIEROGLYPH_SET = [
    "𓀀", "𓀁", "𓀂", "𓀃", "𓀄", "𓀅", "𓀆", "𓀇",
    "𓀈", "𓀉", "𓀊", "𓀋", "𓀌", "𓀍", "𓀎", "𓀏",
]


def generate_random_numbers_key(length: int = 24) -> str:
    """Generate a cryptographically secure numeric key (default: 24 digits)."""
    if not isinstance(length, int) or length < 8 or length > 256:
        raise ValueError("Numeric key length must be between 8 and 256 digits.")
    # secrets.choice avoids modulo bias and uses Python's OS-backed secure RNG.
    alphabet = "0123456789"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_random_glyph_seed(length: int = 32) -> str:
    """Generate a cryptographically secure glyph seed from random bytes."""
    if not isinstance(length, int) or length < 8 or length > 256:
        raise ValueError("Glyph seed length must be between 8 and 256 symbols.")
    return "".join(secrets.choice(HIEROGLYPH_SET) for _ in range(length))


def generate_random_glyph_key(length: int = 64) -> str:
    """Generate a random glyph sequence suitable for the glyph-key field."""
    if not isinstance(length, int) or length < 8 or length > 256:
        raise ValueError("Glyph key length must be between 8 and 256 symbols.")
    return "".join(secrets.choice(HIEROGLYPH_SET) for _ in range(length))


def sha256_file(path: Optional[str]) -> str:
    if not path:
        return hashlib.sha256(b"no-factor").hexdigest()
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def generate_hieroglyph_stream(seed_text: str, length: int = 64) -> str:
    digest = hashlib.sha256((seed_text or "").encode("utf-8")).digest()
    return "".join(HIEROGLYPH_SET[b % len(HIEROGLYPH_SET)] for b in (digest[i % len(digest)] for i in range(length)))


def show_hieroglyph_timeline(stream: str) -> None:
    if not PLOT_AVAILABLE:
        messagebox.showinfo("Optional feature unavailable",
                            "Install matplotlib to display the glyph timeline:\npython -m pip install matplotlib")
        return
    indices = [HIEROGLYPH_SET.index(ch) if ch in HIEROGLYPH_SET else 0 for ch in stream]
    plt.figure("Hieroglyph Timeline")
    plt.plot(range(len(indices)), indices, marker="o")
    plt.title("Hieroglyph Timeline (visualization only)")
    plt.xlabel("Position")
    plt.ylabel("Glyph index")
    plt.grid(True)
    plt.tight_layout()
    plt.show()


def derive_key(pin: str, phrase: str, numbers: str, glyph_seed: str,
               sound_fp: str, voice_fp: str, salt: bytes) -> bytes:
    # PBKDF2 slows offline guessing; optional file hashes add another factor.
    material = "\x1f".join([
        pin, phrase, numbers or "0", glyph_seed,
        sound_fp, voice_fp,
    ]).encode("utf-8")
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32,
                     salt=salt, iterations=KDF_ITERATIONS)
    return base64.urlsafe_b64encode(kdf.derive(material))


def atomic_write(path: str, data: bytes) -> None:
    target = Path(path).expanduser().resolve()
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_path = tempfile.mkstemp(prefix=".mme-", suffix=".tmp", dir=str(target.parent))
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp_path, target)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise


def encrypt_file(input_path: str, output_path: str, sound_path: Optional[str],
                 voice_path: Optional[str], numbers: str, glyph_seed: str,
                 pin: str, phrase: str) -> None:
    if Fernet is None:
        raise RuntimeError("Missing dependency 'cryptography'. Run: python -m pip install cryptography")
    if not os.path.isfile(input_path):
        raise FileNotFoundError("Choose an existing input file.")
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Input and output paths must be different.")
    if not pin or len(pin) < 8:
        raise ValueError("Use a PIN/passphrase of at least 8 characters.")
    if not phrase.strip():
        raise ValueError("A confirmation phrase is required.")
    if not glyph_seed:
        raise ValueError("A glyph seed is required.")

    sound_fp = sha256_file(sound_path)
    voice_fp = sha256_file(voice_path)
    salt = secrets.token_bytes(16)
    key = derive_key(pin, phrase, numbers, glyph_seed, sound_fp, voice_fp, salt)
    fernet = Fernet(key)

    with open(input_path, "rb") as stream:
        plaintext = stream.read()
    token = fernet.encrypt(plaintext)

    metadata = {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "original_filename": os.path.basename(input_path),
        "original_size": len(plaintext),
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "kdf": "PBKDF2-HMAC-SHA256",
        "kdf_iterations": KDF_ITERATIONS,
        "sound_factor_used": bool(sound_path),
        "voice_factor_used": bool(voice_path),
        "sound_sha256": sound_fp,
        "voice_sha256": voice_fp,
        "glyph_stream": generate_hieroglyph_stream(glyph_seed),
        "ciphertext_b64": base64.b64encode(token).decode("ascii"),
    }
    atomic_write(output_path, json.dumps(metadata, ensure_ascii=False, indent=2).encode("utf-8"))


def decrypt_file(input_path: str, output_path: str, sound_path: Optional[str],
                 voice_path: Optional[str], numbers: str, glyph_seed: str,
                 pin: str, phrase: str) -> dict:
    if Fernet is None:
        raise RuntimeError("Missing dependency 'cryptography'. Run: python -m pip install cryptography")
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Input and output paths must be different.")
    with open(input_path, "rb") as stream:
        package = json.load(stream)
    if package.get("format") != FORMAT_NAME or package.get("version") != FORMAT_VERSION:
        raise ValueError("This is not a supported MME v2 package. This fixed version cannot decrypt older v1 packages.")
    if package.get("sound_factor_used") and not sound_path:
        raise ValueError("This package used a sound factor. Select the exact same sound file.")
    if package.get("voice_factor_used") and not voice_path:
        raise ValueError("This package used a voice factor. Select the exact same voice file.")

    sound_fp = sha256_file(sound_path)
    voice_fp = sha256_file(voice_path)
    if not hmac.compare_digest(sound_fp, package.get("sound_sha256", "")):
        raise ValueError("Sound factor does not match the file used during encryption.")
    if not hmac.compare_digest(voice_fp, package.get("voice_sha256", "")):
        raise ValueError("Voice factor does not match the file used during encryption.")

    salt = base64.b64decode(package["salt_b64"])
    key = derive_key(pin, phrase, numbers, glyph_seed, sound_fp, voice_fp, salt)
    try:
        token = base64.b64decode(package["ciphertext_b64"])
        plaintext = Fernet(key).decrypt(token)
    except (InvalidToken, ValueError, KeyError) as exc:
        raise RuntimeError("Decryption failed. Check your PIN, phrase, numbers, glyph seed, and factor files.") from exc

    atomic_write(output_path, plaintext)
    return package


def record_wav(path: str, duration_sec: float = 3.0, samplerate: int = 44100) -> None:
    if not AUDIO_AVAILABLE:
        raise RuntimeError("Audio recording needs sounddevice and scipy. Install with:\npython -m pip install sounddevice scipy")
    audio = sd.rec(int(duration_sec * samplerate), samplerate=samplerate,
                   channels=1, dtype="float32")
    sd.wait()
    audio_int16 = (audio * 32767).clip(-32768, 32767).astype("int16")
    wav_write(path, samplerate, audio_int16)


class EncryptionGUI:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_NAME + " — Fixed Edition")
        self.root.geometry("760x600")
        self.root.minsize(620, 500)
        self.input_file = None
        self.output_file = None
        self.sound_file = None
        self.voice_file = None
        self._build_ui()

    def _build_ui(self):
        outer = ttk.Frame(self.root, padding=12)
        outer.pack(fill="both", expand=True)
        ttk.Label(outer, text="Multimodal AI Encryption", font=("Segoe UI", 16, "bold")).pack(anchor="w")
        ttk.Label(outer, text="Encrypt files with a passphrase, phrase confirmation, random numeric/glyph key generation, and optional audio-file factors.",
                  wraplength=700).pack(anchor="w", pady=(2, 10))

        files = ttk.LabelFrame(outer, text="Files", padding=8)
        files.pack(fill="x", pady=4)
        self.file_labels = {}
        rows = [
            ("input", "Input file", self.select_input),
            ("output", "Encrypted/decrypted output", self.select_output),
            ("sound", "Optional sound factor", self.select_sound),
            ("voice", "Optional voice factor", self.select_voice),
        ]
        for r, (key, label, command) in enumerate(rows):
            ttk.Button(files, text="Choose…", command=command).grid(row=r, column=0, padx=(0, 8), pady=3, sticky="w")
            ttk.Label(files, text=label).grid(row=r, column=1, sticky="w")
            lab = ttk.Label(files, text="Not selected", width=58)
            lab.grid(row=r, column=2, sticky="ew", padx=4)
            self.file_labels[key] = lab
        files.columnconfigure(2, weight=1)

        factors = ttk.LabelFrame(outer, text="Key factors", padding=8)
        factors.pack(fill="x", pady=4)
        self.numbers = self._entry_row(factors, 0, "Numeric key (randomly generated)", "")
        ttk.Button(factors, text="Generate", command=self.generate_numbers_key).grid(
            row=0, column=2, padx=(8, 0), pady=3, sticky="ew")
        self.glyph_seed = self._entry_row(factors, 1, "Glyph seed (randomly generated)", "")
        ttk.Button(factors, text="Generate", command=self.generate_glyph_key).grid(
            row=1, column=2, padx=(8, 0), pady=3, sticky="ew")
        self.pin = self._entry_row(factors, 2, "PIN/passphrase (8+ characters)", "", show="*")
        self.phrase = self._entry_row(factors, 3, "Confirmation phrase", "")

        actions = ttk.Frame(outer)
        actions.pack(fill="x", pady=8)
        ttk.Button(actions, text="Encrypt", command=self.on_encrypt).pack(side="left", padx=(0, 6))
        ttk.Button(actions, text="Decrypt", command=self.on_decrypt).pack(side="left", padx=6)
        ttk.Button(actions, text="Record sound factor", command=lambda: self.record_factor("sound")).pack(side="left", padx=6)
        ttk.Button(actions, text="Record voice factor", command=lambda: self.record_factor("voice")).pack(side="left", padx=6)
        ttk.Button(actions, text="Glyph timeline", command=self.on_timeline).pack(side="left", padx=6)

        self.status = ttk.Label(outer, text="Ready. Choose files and key factors.", anchor="w", wraplength=700)
        self.status.pack(fill="x", pady=(5, 0))
        note = ("Security note: the phrase is not stored in the package. Keep your factors safe. "
                "This app's audio factors are file-hash checks, not voice biometrics.")
        ttk.Label(outer, text=note, wraplength=700).pack(anchor="w", pady=(8, 0))

        if DND_AVAILABLE:
            for key in ("input", "output", "sound", "voice"):
                self.file_labels[key].drop_target_register(DND_FILES)
                self.file_labels[key].dnd_bind("<<Drop>>", lambda event, k=key: self.on_drop(event, k))

    def _entry_row(self, parent, row, label, default, show=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=3)
        entry = ttk.Entry(parent, show=show or "")
        entry.grid(row=row, column=1, sticky="ew", pady=3, padx=(8, 0))
        entry.insert(0, default)
        parent.columnconfigure(1, weight=1)
        parent.columnconfigure(2, weight=0)
        return entry

    def set_file(self, key, path):
        if key == "input" and not os.path.isfile(path):
            raise ValueError("Input must be an existing file.")
        if key in ("sound", "voice") and not os.path.isfile(path):
            raise ValueError("Factor must be an existing file.")
        setattr(self, {"input": "input_file", "output": "output_file",
                       "sound": "sound_file", "voice": "voice_file"}[key], path)
        self.file_labels[key].config(text=path)
        self.status.config(text=f"{key.title()} selected: {path}")

    def on_drop(self, event, key):
        try:
            paths = self.root.tk.splitlist(event.data)
            if paths:
                path = paths[0]
                if key == "output" and os.path.isdir(path):
                    path = os.path.join(path, "encrypted_output.mme")
                self.set_file(key, path)
        except Exception as exc:
            messagebox.showerror("Drag and drop", str(exc))

    def select_input(self):
        path = filedialog.askopenfilename(title="Select input file")
        if path:
            self.set_file("input", path)

    def select_output(self):
        path = filedialog.asksaveasfilename(title="Select output file", defaultextension=".mme",
                                             filetypes=[("MME encrypted package", "*.mme"), ("All files", "*.*")])
        if path:
            self.set_file("output", path)

    def select_sound(self):
        path = filedialog.askopenfilename(title="Select sound factor file")
        if path:
            self.set_file("sound", path)

    def select_voice(self):
        path = filedialog.askopenfilename(title="Select voice factor file")
        if path:
            self.set_file("voice", path)

    def record_factor(self, key):
        if not AUDIO_AVAILABLE:
            messagebox.showerror("Audio unavailable",
                "Install optional recording packages:\npython -m pip install sounddevice scipy")
            return
        path = filedialog.asksaveasfilename(title="Save recording", defaultextension=".wav",
                                             filetypes=[("WAV audio", "*.wav")])
        if not path:
            return
        try:
            self.status.config(text="Recording for 3 seconds…")
            self.root.update_idletasks()
            record_wav(path)
            self.set_file(key, path)
        except Exception as exc:
            messagebox.showerror("Recording failed", str(exc))
            self.status.config(text="Recording failed.")

    def generate_numbers_key(self):
        try:
            key = generate_random_numbers_key(24)
            self.numbers.delete(0, "end")
            self.numbers.insert(0, key)
            self.status.config(text="Generated a new 24-digit numeric key. Save it securely; it is required for decryption.")
        except Exception as exc:
            messagebox.showerror("Key generation failed", str(exc))

    def generate_glyph_key(self):
        try:
            # A random 32-symbol glyph seed is used as the key input. The timeline
            # visualization remains decorative and is not itself an encryption key.
            key = generate_random_glyph_seed(32)
            self.glyph_seed.delete(0, "end")
            self.glyph_seed.insert(0, key)
            self.status.config(text="Generated a new random glyph seed. Save it securely; it is required for decryption.")
        except Exception as exc:
            messagebox.showerror("Key generation failed", str(exc))

    def get_factors(self):
        numbers = self.numbers.get().strip()
        seed = self.glyph_seed.get().strip()
        pin = self.pin.get()
        phrase = self.phrase.get()
        if not seed:
            seed = simpledialog.askstring("Glyph seed", "Enter your glyph seed:", parent=self.root) or ""
            if seed:
                self.glyph_seed.delete(0, "end")
                self.glyph_seed.insert(0, seed)
        if not pin:
            pin = simpledialog.askstring("PIN/passphrase", "Enter your PIN/passphrase (8+ characters):",
                                         parent=self.root, show="*") or ""
        if not phrase:
            phrase = simpledialog.askstring("Confirmation phrase", "Enter the exact confirmation phrase:",
                                            parent=self.root) or ""
        return numbers, seed, pin, phrase

    def on_encrypt(self):
        if not self.input_file or not self.output_file:
            messagebox.showerror("Missing files", "Select both an input file and an output file.")
            return
        try:
            numbers, seed, pin, phrase = self.get_factors()
            encrypt_file(self.input_file, self.output_file, self.sound_file, self.voice_file,
                         numbers, seed, pin, phrase)
            self.status.config(text="Encryption complete.")
            messagebox.showinfo("Success", "File encrypted successfully.")
        except Exception as exc:
            self.status.config(text=f"Encryption failed: {exc}")
            messagebox.showerror("Encryption failed", str(exc))

    def on_decrypt(self):
        if not self.input_file or not self.output_file:
            messagebox.showerror("Missing files", "Select the encrypted input package and output path.")
            return
        try:
            numbers, seed, pin, phrase = self.get_factors()
            package = decrypt_file(self.input_file, self.output_file, self.sound_file, self.voice_file,
                                   numbers, seed, pin, phrase)
            self.status.config(text="Decryption complete.")
            messagebox.showinfo("Success", f"Decryption complete.\nRecovered {package.get('original_filename', 'file')}.")
        except Exception as exc:
            self.status.config(text=f"Decryption failed: {exc}")
            messagebox.showerror("Decryption failed", str(exc))

    def on_timeline(self):
        seed = self.glyph_seed.get().strip()
        if not seed:
            seed = simpledialog.askstring("Glyph seed", "Enter your glyph seed:", parent=self.root) or ""
        if seed:
            show_hieroglyph_timeline(generate_hieroglyph_stream(seed))


def main():
    if Fernet is None:
        # Use a minimal Tk window if possible so the failure is clear and actionable.
        try:
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Missing dependency",
                "The required package 'cryptography' is not installed.\n\n"
                "Open Command Prompt and run:\npy -m pip install cryptography")
            root.destroy()
        except Exception:
            print("Missing dependency: cryptography. Install with: py -m pip install cryptography")
        return

    root = TkinterDnD.Tk() if DND_AVAILABLE else tk.Tk()
    app = EncryptionGUI(root)
    if not DND_AVAILABLE:
        app.status.config(text="Ready. Drag-and-drop is disabled; file selection still works. Install tkinterdnd2 to enable it.")
    root.mainloop()


if __name__ == "__main__":
    try:
        main()
    except Exception:
        error = traceback.format_exc()
        try:
            with open("multimodal_encryption_crash.log", "a", encoding="utf-8") as log:
                log.write("\n--- " + datetime.datetime.now().isoformat() + " ---\n" + error)
        except Exception:
            pass
        print(error, file=sys.stderr)
        try:
            messagebox.showerror("Startup error", "The application could not start:\n\n" + error[-2500:])
        except Exception:
            pass
