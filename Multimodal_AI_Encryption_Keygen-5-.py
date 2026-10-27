#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DominionDeck – Full Fusion
Multimodal AI Encryption + Alien Security Mode (Extreme Lockdown) + Drive Encryption + Plugins

Core requirements:
    pip install cryptography
    pip install argon2-cffi

Optional features:
    pip install tkinterdnd2       # drag and drop
    pip install sounddevice scipy # record sound/voice samples
    pip install matplotlib        # glyph timeline chart
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
import platform
import time
import string
from datetime import datetime as dt_utc, timedelta
from pathlib import Path
from typing import Optional, Callable, Dict, Any, List, Tuple

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

# --- Crypto dependencies ---

try:
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.fernet import Fernet, InvalidToken  # kept for compatibility
except ImportError:
    Fernet = None
    InvalidToken = Exception
    PBKDF2HMAC = None
    AESGCM = None
    Ed25519PrivateKey = None
    Ed25519PublicKey = None

try:
    from argon2.low_level import (
        hash_secret_raw,
        Type as Argon2Type,
    )
    ARGON2_AVAILABLE = True
except ImportError:
    ARGON2_AVAILABLE = False

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

APP_NAME = "DominionDeck – Full Fusion Node"
FORMAT_NAME = "MME-PACKAGE"
FORMAT_VERSION = 3
KDF_ITERATIONS_PBKDF2 = 600_000
ARGON2_PARAMS = {
    "time_cost": 4,
    "memory_cost": 1024 * 64,  # 64 MiB
    "parallelism": 2,
    "hash_len": 32,
    "type": Argon2Type.ID if ARGON2_AVAILABLE else None,
}
HIEROGLYPH_SET = [
    "𓀀", "𓀁", "𓀂", "𓀃", "𓀄", "𓀅", "𓀆", "𓀇",
    "𓀈", "𓀉", "𓀊", "𓀋", "𓀌", "𓀍", "𓀎", "𓀏",
]

LOCK_STATE_FILE = Path("dominion_lock_state.json")
MAX_FAILED_ATTEMPTS = 10
LOCK_DURATION_HOURS = 24

# --- Plugin API for external factor modules (MME side) ---

FactorPlugin = Callable[[Dict[str, Any]], bytes]
FACTOR_PLUGINS: List[FactorPlugin] = []


def register_factor_plugin(plugin: FactorPlugin) -> None:
    FACTOR_PLUGINS.append(plugin)


# --- Hardware factor (TPM/HSM-style hook) ---

def get_hardware_secret() -> Optional[bytes]:
    env_secret = os.environ.get("MME_HARDWARE_SECRET")
    if env_secret:
        return hashlib.sha256(env_secret.encode("utf-8")).digest()
    hw_path = Path("mme_hardware_secret.bin")
    if hw_path.is_file():
        data = hw_path.read_bytes()
        return hashlib.sha256(data).digest()
    return None


# --- Utility functions ---

def sha256_file(path: Optional[str]) -> str:
    if not path:
        return hashlib.sha256(b"no-factor").hexdigest()
    h = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def validate_factor_file(path: Optional[str], label: str, max_size_mb: int = 64) -> None:
    if not path:
        return
    p = Path(path)
    if not p.is_file():
        raise ValueError(f"{label} factor must be an existing file.")
    size = p.stat().st_size
    if size <= 0:
        raise ValueError(f"{label} factor file is empty.")
    if size > max_size_mb * 1024 * 1024:
        raise ValueError(f"{label} factor file exceeds {max_size_mb} MB limit.")
    ext = p.suffix.lower()
    if label in ("Sound", "Voice") and ext not in (".wav", ".flac", ".mp3", ".ogg"):
        raise ValueError(f"{label} factor file should be an audio type (wav/flac/mp3/ogg).")


def generate_hieroglyph_stream(seed_text: str, length: int = 64) -> str:
    digest = hashlib.sha256((seed_text or "").encode("utf-8")).digest()
    return "".join(
        HIEROGLYPH_SET[b % len(HIEROGLYPH_SET)]
        for b in (digest[i % len(digest)] for i in range(length))
    )


def show_hieroglyph_timeline(stream: str) -> None:
    if not PLOT_AVAILABLE:
        messagebox.showinfo(
            "Optional feature unavailable",
            "Install matplotlib to display the glyph timeline:\npython -m pip install matplotlib",
        )
        return
    indices = [HIEROGLYPH_SET.index(ch) if ch in HIEROGLYPH_SET else 0 for ch in stream]
    plt.figure("District 10 Glyph Timeline")
    plt.plot(range(len(indices)), indices, marker="o", color="#00ffcc")
    plt.title("Alien Settlement Glyph Timeline (visualization only)")
    plt.xlabel("Position")
    plt.ylabel("Glyph index")
    plt.grid(True, color="#333333")
    plt.tight_layout()
    plt.show()


# --- Key generators (PIN, glyph seed, numeric layer) ---

def generate_random_pin(length: int = 16) -> str:
    alphabet = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*_-"
    return "".join(secrets.choice(alphabet) for _ in range(length))


def generate_random_glyph_seed(length: int = 24) -> str:
    core = "".join(secrets.choice("0123456789abcdef") for _ in range(length))
    glyph_hint = HIEROGLYPH_SET[secrets.randbelow(len(HIEROGLYPH_SET))]
    return f"{core}-{glyph_hint}"


def generate_random_numeric_layer(length: int = 12) -> str:
    return "".join(secrets.choice("0123456789") for _ in range(length))


# --- KDFs: PBKDF2 + Argon2id ---

def derive_key_material(
    pin: str,
    phrase: str,
    numbers: str,
    glyph_seed: str,
    sound_fp: str,
    voice_fp: str,
    hardware_secret: Optional[bytes],
) -> bytes:
    base_material = "\x1f".join(
        [
            pin,
            phrase,
            numbers or "0",
            glyph_seed,
            sound_fp,
            voice_fp,
        ]
    ).encode("utf-8")
    if hardware_secret:
        base_material = hashlib.sha256(base_material + hardware_secret).digest()
    for plugin in FACTOR_PLUGINS:
        extra = plugin(
            {
                "pin": pin,
                "phrase": phrase,
                "numbers": numbers,
                "glyph_seed": glyph_seed,
                "sound_fp": sound_fp,
                "voice_fp": voice_fp,
                "hardware_secret": hardware_secret,
            }
        )
        base_material = hashlib.sha256(base_material + extra).digest()
    return base_material


def kdf_pbkdf2(material: bytes, salt: bytes) -> bytes:
    if PBKDF2HMAC is None:
        raise RuntimeError("PBKDF2HMAC unavailable. Install cryptography.")
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=KDF_ITERATIONS_PBKDF2,
    )
    return kdf.derive(material)


def kdf_argon2(material: bytes, salt: bytes) -> bytes:
    if not ARGON2_AVAILABLE:
        raise RuntimeError("Argon2id is not available. Install argon2-cffi.")
    return hash_secret_raw(
        secret=material,
        salt=salt,
        time_cost=ARGON2_PARAMS["time_cost"],
        memory_cost=ARGON2_PARAMS["memory_cost"],
        parallelism=ARGON2_PARAMS["parallelism"],
        hash_len=ARGON2_PARAMS["hash_len"],
        type=ARGON2_PARAMS["type"],
    )


def derive_key(
    pin: str,
    phrase: str,
    numbers: str,
    glyph_seed: str,
    sound_fp: str,
    voice_fp: str,
    salt: bytes,
    kdf_mode: str = "argon2id",
) -> Tuple[bytes, str]:
    hardware_secret = get_hardware_secret()
    material = derive_key_material(pin, phrase, numbers, glyph_seed, sound_fp, voice_fp, hardware_secret)
    if kdf_mode == "pbkdf2":
        key_raw = kdf_pbkdf2(material, salt)
        kdf_name = "PBKDF2-HMAC-SHA256"
    else:
        key_raw = kdf_argon2(material, salt)
        kdf_name = "Argon2id"
    return base64.urlsafe_b64encode(key_raw), kdf_name


# --- Ed25519 signing & tamper-evident header ---

def generate_ed25519_keypair() -> Tuple[bytes, bytes]:
    if Ed25519PrivateKey is None:
        raise RuntimeError("Ed25519 unavailable. Install cryptography.")
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    priv_bytes = priv.private_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PrivateFormat.Raw,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_bytes = pub.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return priv_bytes, pub_bytes


def sign_package_header(priv_bytes: bytes, header_bytes: bytes) -> bytes:
    priv = Ed25519PrivateKey.from_private_bytes(priv_bytes)
    return priv.sign(header_bytes)


def verify_package_header(pub_bytes: bytes, header_bytes: bytes, signature: bytes) -> bool:
    pub = Ed25519PublicKey.from_public_bytes(pub_bytes)
    try:
        pub.verify(signature, header_bytes)
        return True
    except Exception:
        return False


def compute_header_hmac(header_bytes: bytes, key: bytes) -> str:
    return hmac.new(key, header_bytes, hashlib.sha256).hexdigest()


# --- Atomic write ---

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


# --- Streaming encryption (AES-GCM over chunks) ---

def encrypt_stream(input_path: str, key: bytes) -> Dict[str, Any]:
    if AESGCM is None:
        raise RuntimeError("AESGCM unavailable. cryptography aead support required.")
    aesgcm = AESGCM(key)
    nonce = secrets.token_bytes(12)
    chunk_size = 1024 * 1024
    ciphertext_chunks = []
    with open(input_path, "rb") as stream:
        while True:
            chunk = stream.read(chunk_size)
            if not chunk:
                break
            ct = aesgcm.encrypt(nonce, chunk, None)
            ciphertext_chunks.append(base64.b64encode(ct).decode("ascii"))
    return {
        "nonce_b64": base64.b64encode(nonce).decode("ascii"),
        "chunks": ciphertext_chunks,
        "chunk_size": chunk_size,
    }


def decrypt_stream(stream_info: Dict[str, Any], key: bytes, output_path: str) -> None:
    if AESGCM is None:
        raise RuntimeError("AESGCM unavailable. cryptography aead support required.")
    aesgcm = AESGCM(key)
    nonce = base64.b64decode(stream_info["nonce_b64"])
    chunks = stream_info["chunks"]
    with tempfile.NamedTemporaryFile(delete=False) as tmp:
        for ct_b64 in chunks:
            ct = base64.b64decode(ct_b64)
            pt = aesgcm.decrypt(nonce, ct, None)
            tmp.write(pt)
        tmp.flush()
        os.fsync(tmp.fileno())
        tmp_path = tmp.name
    atomic_write(output_path, Path(tmp_path).read_bytes())
    try:
        os.unlink(tmp_path)
    except OSError:
        pass


# --- Core encrypt/decrypt with hardened package ---

def encrypt_file(
    input_path: str,
    output_path: str,
    sound_path: Optional[str],
    voice_path: Optional[str],
    numbers: str,
    glyph_seed: str,
    pin: str,
    phrase: str,
    kdf_mode: str = "argon2id",
) -> None:
    if AESGCM is None or Ed25519PrivateKey is None:
        raise RuntimeError(
            "Missing crypto dependencies. Install:\n"
            "python -m pip install cryptography argon2-cffi"
        )
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

    validate_factor_file(sound_path, "Sound")
    validate_factor_file(voice_path, "Voice")

    sound_fp = sha256_file(sound_path)
    voice_fp = sha256_file(voice_path)
    salt = secrets.token_bytes(32)
    key_b64, kdf_name = derive_key(pin, phrase, numbers, glyph_seed, sound_fp, voice_fp, salt, kdf_mode=kdf_mode)
    key_raw = base64.urlsafe_b64decode(key_b64)

    stream_info = encrypt_stream(input_path, key_raw)

    aesgcm_meta = AESGCM(key_raw)
    meta_nonce = secrets.token_bytes(12)
    glyph_stream = generate_hieroglyph_stream(glyph_seed)
    metadata_plain = {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "original_filename": os.path.basename(input_path),
        "kdf": kdf_name,
        "kdf_mode": kdf_mode,
        "kdf_iterations_pbkdf2": KDF_ITERATIONS_PBKDF2,
        "argon2_params": ARGON2_PARAMS if ARGON2_AVAILABLE else None,
        "sound_factor_used": bool(sound_path),
        "voice_factor_used": bool(voice_path),
        "sound_sha256": sound_fp,
        "voice_sha256": voice_fp,
        "glyph_stream": glyph_stream,
    }
    metadata_cipher = aesgcm_meta.encrypt(
        meta_nonce,
        json.dumps(metadata_plain, ensure_ascii=False).encode("utf-8"),
        None,
    )

    priv_bytes, pub_bytes = generate_ed25519_keypair()
    header = {
        "format": FORMAT_NAME,
        "version": FORMAT_VERSION,
        "salt_b64": base64.b64encode(salt).decode("ascii"),
        "meta_nonce_b64": base64.b64encode(meta_nonce).decode("ascii"),
        "metadata_cipher_b64": base64.b64encode(metadata_cipher).decode("ascii"),
        "stream": stream_info,
        "public_key_b64": base64.b64encode(pub_bytes).decode("ascii"),
        "sound_factor_used": bool(sound_path),
        "voice_factor_used": bool(voice_path),
    }
    header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = sign_package_header(priv_bytes, header_bytes)
    hmac_key = hashlib.sha256(
        base64.b64decode(header["salt_b64"]) + pub_bytes
    ).digest()
    header_hmac = compute_header_hmac(header_bytes, hmac_key)

    package = {
        "header": header,
        "signature_b64": base64.b64encode(signature).decode("ascii"),
        "header_hmac": header_hmac,
        "note": "Tamper-evident MME v3 package with Ed25519 signature and HMAC header.",
    }

    atomic_write(output_path, json.dumps(package, ensure_ascii=False, indent=2).encode("utf-8"))


def decrypt_file(
    input_path: str,
    output_path: str,
    sound_path: Optional[str],
    voice_path: Optional[str],
    numbers: str,
    glyph_seed: str,
    pin: str,
    phrase: str,
) -> Dict[str, Any]:
    if AESGCM is None or Ed25519PublicKey is None:
        raise RuntimeError(
            "Missing crypto dependencies. Install:\n"
            "python -m pip install cryptography argon2-cffi"
        )
    if os.path.abspath(input_path) == os.path.abspath(output_path):
        raise ValueError("Input and output paths must be different.")
    with open(input_path, "rb") as stream:
        package = json.load(stream)

    header = package.get("header", {})
    if header.get("format") != FORMAT_NAME or header.get("version") != FORMAT_VERSION:
        raise ValueError("Unsupported package format/version for MME v3 hardened edition.")

    validate_factor_file(sound_path, "Sound")
    validate_factor_file(voice_path, "Voice")

    sound_fp = sha256_file(sound_path)
    voice_fp = sha256_file(voice_path)

    if header.get("sound_factor_used") and not sound_path:
        raise ValueError("This package used a sound factor. Select the exact same sound file.")
    if header.get("voice_factor_used") and not voice_path:
        raise ValueError("This package used a voice factor. Select the exact same voice file.")

    header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
    signature = base64.b64decode(package["signature_b64"])
    pub_bytes = base64.b64decode(header["public_key_b64"])
    if not verify_package_header(pub_bytes, header_bytes, signature):
        raise RuntimeError("Package signature verification failed. Tampering suspected.")

    hmac_key = hashlib.sha256(
        base64.b64decode(header["salt_b64"]) + pub_bytes
    ).digest()
    expected_hmac = compute_header_hmac(header_bytes, hmac_key)
    if not hmac.compare_digest(expected_hmac, package.get("header_hmac", "")):
        raise RuntimeError("Header HMAC mismatch. Tampering suspected.")

    salt = base64.b64decode(header["salt_b64"])
    kdf_mode = header.get("kdf_mode", "argon2id")
    key_b64, _ = derive_key(pin, phrase, numbers, glyph_seed, sound_fp, voice_fp, salt, kdf_mode=kdf_mode)
    key_raw = base64.urlsafe_b64decode(key_b64)

    aesgcm_meta = AESGCM(key_raw)
    meta_nonce = base64.b64decode(header["meta_nonce_b64"])
    metadata_cipher = base64.b64decode(header["metadata_cipher_b64"])
    try:
        metadata_plain_bytes = aesgcm_meta.decrypt(meta_nonce, metadata_cipher, None)
        metadata_plain = json.loads(metadata_plain_bytes.decode("utf-8"))
    except Exception as exc:
        raise RuntimeError(
            "Metadata decryption failed. Check your PIN, phrase, numbers, glyph seed, and factor files."
        ) from exc

    if not hmac.compare_digest(sound_fp, metadata_plain.get("sound_sha256", "")):
        raise ValueError("Sound factor does not match the file used during encryption.")
    if not hmac.compare_digest(voice_fp, metadata_plain.get("voice_sha256", "")):
        raise ValueError("Voice factor does not match the file used during encryption.")

    stream_info = header["stream"]
    decrypt_stream(stream_info, key_raw, output_path)

    return metadata_plain


# --- Audio recording ---

def record_wav(path: str, duration_sec: float = 3.0, samplerate: int = 44100) -> None:
    if not AUDIO_AVAILABLE:
        raise RuntimeError(
            "Audio recording needs sounddevice and scipy. Install with:\npython -m pip install sounddevice scipy"
        )
    audio = sd.rec(int(duration_sec * samplerate), samplerate=samplerate, channels=1, dtype="float32")
    sd.wait()
    audio_int16 = (audio * 32767).clip(-32768, 32767).astype("int16")
    wav_write(path, samplerate, audio_int16)


# --- Drive enumeration (Windows real) ---

def list_windows_drives() -> List[Tuple[str, str]]:
    drives: List[Tuple[str, str]] = []
    if platform.system().lower() != "windows":
        return drives
    import ctypes

    DRIVE_UNKNOWN = 0
    DRIVE_NO_ROOT_DIR = 1
    DRIVE_REMOVABLE = 2
    DRIVE_FIXED = 3
    DRIVE_REMOTE = 4
    DRIVE_CDROM = 5
    DRIVE_RAMDISK = 6

    GetDriveTypeW = ctypes.windll.kernel32.GetDriveTypeW
    for letter in "ABCDEFGHIJKLMNOPQRSTUVWXYZ":
        root = f"{letter}:\\"
        if not os.path.exists(root):
            continue
        dtype = GetDriveTypeW(root)
        if dtype == DRIVE_REMOVABLE:
            label = "Removable/USB"
        elif dtype == DRIVE_FIXED:
            label = "Fixed"
        elif dtype == DRIVE_CDROM:
            label = "CDROM"
        elif dtype == DRIVE_REMOTE:
            label = "Network"
        elif dtype == DRIVE_RAMDISK:
            label = "RAMDisk"
        else:
            label = "Unknown"
        drives.append((root, label))
    return drives


def encrypt_drive_contents(
    drive_root: str,
    sound_path: Optional[str],
    voice_path: Optional[str],
    numbers: str,
    glyph_seed: str,
    pin: str,
    phrase: str,
    kdf_mode: str = "argon2id",
    status_callback: Optional[Callable[[str], None]] = None,
) -> None:
    if status_callback is None:
        status_callback = lambda msg: None

    validate_factor_file(sound_path, "Sound")
    validate_factor_file(voice_path, "Voice")

    sound_fp = sha256_file(sound_path)
    voice_fp = sha256_file(voice_path)
    salt = secrets.token_bytes(32)
    key_b64, kdf_name = derive_key(pin, phrase, numbers, glyph_seed, sound_fp, voice_fp, salt, kdf_mode=kdf_mode)
    key_raw = base64.urlsafe_b64decode(key_b64)

    status_callback(f"Scanning drive {drive_root} for files to encrypt…")

    for root, dirs, files in os.walk(drive_root):
        lower_root = root.lower()
        if any(
            lower_root.startswith(os.path.join(drive_root.lower(), p))
            for p in ("windows", "program files", "program files (x86)", "programdata")
        ):
            continue
        for name in files:
            src = os.path.join(root, name)
            if src.lower().endswith(".mme"):
                continue
            try:
                rel = os.path.relpath(src, drive_root)
                out_dir = os.path.join(drive_root, "_mme_encrypted")
                out_path = os.path.join(out_dir, rel + ".mme")
                Path(out_path).parent.mkdir(parents=True, exist_ok=True)

                stream_info = encrypt_stream(src, key_raw)

                aesgcm_meta = AESGCM(key_raw)
                meta_nonce = secrets.token_bytes(12)
                glyph_stream = generate_hieroglyph_stream(glyph_seed)
                metadata_plain = {
                    "format": FORMAT_NAME,
                    "version": FORMAT_VERSION,
                    "created_at_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                    "original_filename": os.path.basename(src),
                    "original_path": src,
                    "kdf": kdf_name,
                    "kdf_mode": kdf_mode,
                    "kdf_iterations_pbkdf2": KDF_ITERATIONS_PBKDF2,
                    "argon2_params": ARGON2_PARAMS if ARGON2_AVAILABLE else None,
                    "sound_factor_used": bool(sound_path),
                    "voice_factor_used": bool(voice_path),
                    "sound_sha256": sound_fp,
                    "voice_sha256": voice_fp,
                    "glyph_stream": glyph_stream,
                    "bulk_drive_root": drive_root,
                }
                metadata_cipher = aesgcm_meta.encrypt(
                    meta_nonce,
                    json.dumps(metadata_plain, ensure_ascii=False).encode("utf-8"),
                    None,
                )

                priv_bytes, pub_bytes = generate_ed25519_keypair()
                header = {
                    "format": FORMAT_NAME,
                    "version": FORMAT_VERSION,
                    "salt_b64": base64.b64encode(salt).decode("ascii"),
                    "meta_nonce_b64": base64.b64encode(meta_nonce).decode("ascii"),
                    "metadata_cipher_b64": base64.b64encode(metadata_cipher).decode("ascii"),
                    "stream": stream_info,
                    "public_key_b64": base64.b64encode(pub_bytes).decode("ascii"),
                    "sound_factor_used": bool(sound_path),
                    "voice_factor_used": bool(voice_path),
                }
                header_bytes = json.dumps(header, ensure_ascii=False, sort_keys=True).encode("utf-8")
                signature = sign_package_header(priv_bytes, header_bytes)
                hmac_key = hashlib.sha256(
                    base64.b64decode(header["salt_b64"]) + pub_bytes
                ).digest()
                header_hmac = compute_header_hmac(header_bytes, hmac_key)

                package = {
                    "header": header,
                    "signature_b64": base64.b64encode(signature).decode("ascii"),
                    "header_hmac": header_hmac,
                    "note": f"Bulk drive encryption package from {drive_root}.",
                }

                atomic_write(out_path, json.dumps(package, ensure_ascii=False, indent=2).encode("utf-8"))
                status_callback(f"Encrypted: {src} -> {out_path}")
            except Exception as exc:
                status_callback(f"Failed to encrypt {src}: {exc}")


# ---------------------------------------------------------------------------
# DominionDeck – Lockout state management
# ---------------------------------------------------------------------------

class LockoutState:
    def __init__(self, path: Path):
        self.path = path
        self.failed_attempts = 0
        self.lock_until: Optional[dt_utc] = None
        self.tamper_count = 0
        self._load()

    def _load(self):
        if not self.path.exists():
            self._save()
            return
        try:
            raw = self.path.read_text(encoding="utf-8")
            data = json.loads(raw)
            self.failed_attempts = int(data.get("failed_attempts", 0))
            self.tamper_count = int(data.get("tamper_count", 0))
            lu = data.get("lock_until", None)
            if lu:
                self.lock_until = dt_utc.fromisoformat(lu)
            else:
                self.lock_until = None
        except Exception:
            self.tamper_count += 1
            self.failed_attempts = MAX_FAILED_ATTEMPTS
            self.lock_until = dt_utc.utcnow() + timedelta(hours=LOCK_DURATION_HOURS + self.tamper_count)
            self._save()

    def _save(self):
        data = {
            "failed_attempts": self.failed_attempts,
            "tamper_count": self.tamper_count,
            "lock_until": self.lock_until.isoformat() if self.lock_until else None,
        }
        self.path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def is_locked(self) -> bool:
        if self.lock_until is None:
            return False
        now = dt_utc.utcnow()
        if now >= self.lock_until:
            self.failed_attempts = 0
            self.lock_until = None
            self._save()
            return False
        return True

    def register_failure(self):
        self.failed_attempts += 1
        if self.failed_attempts >= MAX_FAILED_ATTEMPTS and not self.is_locked():
            self.lock_until = dt_utc.utcnow() + timedelta(hours=LOCK_DURATION_HOURS)
        self._save()

    def force_lock_extend(self, extra_hours: int = 1):
        if not self.lock_until:
            self.lock_until = dt_utc.utcnow() + timedelta(hours=LOCK_DURATION_HOURS + extra_hours)
        else:
            self.lock_until = self.lock_until + timedelta(hours=extra_hours)
        self._save()


# ---------------------------------------------------------------------------
# Plugin API skeleton for external factor modules (Dominion side)
# ---------------------------------------------------------------------------

class FactorPluginManager:
    def __init__(self, plugin_dir: Path):
        self.plugin_dir = plugin_dir
        self.plugins: Dict[str, Dict[str, Any]] = {}
        self._load_plugins()

    def _load_plugins(self):
        if not self.plugin_dir.exists():
            self.plugin_dir.mkdir(parents=True, exist_ok=True)
        for pyfile in self.plugin_dir.glob("*.py"):
            name = pyfile.stem
            try:
                spec: Dict[str, Any] = {}
                code = pyfile.read_text(encoding="utf-8")
                exec(code, {"__builtins__": {}}, spec)
                self.plugins[name] = spec
            except Exception:
                continue

    def list_plugins(self):
        return list(self.plugins.keys())

    def apply_factor(self, name: str, context: dict) -> dict:
        plugin = self.plugins.get(name)
        if not plugin:
            return context
        func = plugin.get("apply_factor")
        if callable(func):
            try:
                return func(context)
            except Exception:
                return context
        return context


# ---------------------------------------------------------------------------
# Alien Lockdown full-screen UI
# ---------------------------------------------------------------------------

class AlienLockdownWindow(tk.Toplevel):
    def __init__(self, master, lock_state: LockoutState):
        super().__init__(master)
        self.lock_state = lock_state
        self.title("ALIEN SECURITY LOCKDOWN")
        self.configure(bg="#050308")
        self.attributes("-fullscreen", True)
        self.protocol("WM_DELETE_WINDOW", self._block_close)

        self._build_ui()
        self._update_countdown()

    def _build_ui(self):
        glyph_font = ("Consolas", 32, "bold")
        msg_font = ("Consolas", 18, "bold")

        frame = tk.Frame(self, bg="#050308")
        frame.pack(expand=True, fill="both")

        glyph_label = tk.Label(
            frame,
            text="⟟⟒⌰⟟⋏  ⊑⟒⟊⟟⟒⋏  ⊑⟒⌰⌰",
            fg="#39ff14",
            bg="#050308",
            font=glyph_font
        )
        glyph_label.pack(pady=40)

        self.msg_label = tk.Label(
            frame,
            text="UNAUTHORIZED ACCESS DETECTED\nSYSTEM IS NOW LOCKED FOR 24 HOURS",
            fg="#ff004f",
            bg="#050308",
            font=msg_font,
            justify="center"
        )
        self.msg_label.pack(pady=20)

        self.countdown_label = tk.Label(
            frame,
            text="LOCKDOWN REMAINING: --:--:--",
            fg="#00e5ff",
            bg="#050308",
            font=("Consolas", 20, "bold")
        )
        self.countdown_label.pack(pady=20)

        sub_label = tk.Label(
            frame,
            text="NO INPUT WILL BE ACCEPTED.\nTAMPERING WILL EXTEND LOCKDOWN.",
            fg="#ffcc00",
            bg="#050308",
            font=("Consolas", 14, "bold")
        )
        sub_label.pack(pady=40)

    def _block_close(self):
        pass

    def _update_countdown(self):
        if not self.lock_state.lock_until:
            self.countdown_label.config(text="LOCKDOWN REMAINING: 00:00:00")
            return
        now = dt_utc.utcnow()
        remaining = self.lock_state.lock_until - now
        if remaining.total_seconds() <= 0:
            self.countdown_label.config(text="LOCKDOWN REMAINING: 00:00:00")
            return
        hours, remainder = divmod(int(remaining.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)
        self.countdown_label.config(
            text=f"LOCKDOWN REMAINING: {hours:02d}:{minutes:02d}:{seconds:02d}"
        )
        self.after(1000, self._update_countdown)


# ---------------------------------------------------------------------------
# Dominion Security Panel (Alien Security Mode) – embedded in fusion app
# ---------------------------------------------------------------------------

class DominionSecurityPanel(ttk.Frame):
    def __init__(self, master, lock_state: LockoutState, plugin_manager: FactorPluginManager):
        super().__init__(master, style="Alien.TFrame")
        self.lock_state = lock_state
        self.plugin_manager = plugin_manager

        self.pin_var = tk.StringVar()
        self.glycine_var = tk.StringVar()
        self.numeric_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Ready.")

        self._build_ui()

    def _build_ui(self):
        root_frame = ttk.Frame(self, style="Alien.TFrame")
        root_frame.pack(expand=True, fill="both", padx=10, pady=10)

        left = ttk.Frame(root_frame, style="Alien.TFrame")
        left.pack(side="left", fill="y", padx=10, pady=10)

        title = ttk.Label(
            left,
            text="ALIEN ACCESS PANEL",
            style="Alien.TLabel",
            font=("Consolas", 16, "bold")
        )
        title.pack(pady=10)

        ttk.Label(left, text="PIN:", style="Alien.TLabel").pack(anchor="w")
        self.pin_entry = ttk.Entry(left, textvariable=self.pin_var, show="*")
        self.pin_entry.pack(fill="x", pady=4)

        ttk.Label(left, text="Glycine Key:", style="Alien.TLabel").pack(anchor="w")
        self.glycine_entry = ttk.Entry(left, textvariable=self.glycine_var, show="*")
        self.glycine_entry.pack(fill="x", pady=4)

        ttk.Label(left, text="Numeric Layer:", style="Alien.TLabel").pack(anchor="w")
        self.numeric_entry = ttk.Entry(left, textvariable=self.numeric_var, show="*")
        self.numeric_entry.pack(fill="x", pady=4)

        auth_btn = ttk.Button(
            left,
            text="AUTHORIZE",
            style="Alien.TButton",
            command=self._handle_authorize
        )
        auth_btn.pack(pady=10, fill="x")

        ttk.Label(left, text="Key Generators", style="Alien.TLabel").pack(anchor="w", pady=(20, 5))

        ttk.Button(
            left,
            text="Generate PIN",
            style="Alien.TButton",
            command=self._gen_pin
        ).pack(fill="x", pady=2)

        ttk.Button(
            left,
            text="Generate Glycine Key",
            style="Alien.TButton",
            command=self._gen_glycine
        ).pack(fill="x", pady=2)

        ttk.Button(
            left,
            text="Generate Numeric Layer",
            style="Alien.TButton",
            command=self._gen_numeric
        ).pack(fill="x", pady=2)

        ttk.Label(left, text="Factor Plugins:", style="Alien.TLabel").pack(anchor="w", pady=(20, 5))
        self.plugin_list = tk.Listbox(left, height=6, bg="#050308", fg="#39ff14")
        self.plugin_list.pack(fill="both", pady=4)
        for name in self.plugin_manager.list_plugins():
            self.plugin_list.insert(tk.END, name)

        right = ttk.Frame(root_frame, style="Alien.TFrame")
        right.pack(side="left", expand=True, fill="both", padx=10, pady=10)

        drives_label = ttk.Label(
            right,
            text="DRIVE ENCRYPTION (REAL + SIM)",
            style="Alien.TLabel",
            font=("Consolas", 16, "bold")
        )
        drives_label.pack(pady=10)

        self.drive_tree = ttk.Treeview(
            right,
            columns=("drive", "type"),
            show="headings",
            height=15
        )
        self.drive_tree.heading("drive", text="Drive")
        self.drive_tree.heading("type", text="Type")
        self.drive_tree.column("drive", width=160, anchor="w")
        self.drive_tree.column("type", width=120, anchor="center")
        self.drive_tree.pack(expand=True, fill="both", pady=10)

        btn_frame = ttk.Frame(right, style="Alien.TFrame")
        btn_frame.pack(fill="x", pady=10)

        ttk.Button(
            btn_frame,
            text="Encrypt Selected Drive (REAL)",
            style="Alien.TButton",
            command=self._encrypt_selected_drive_real
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Encrypt Selected Drive (SIM)",
            style="Alien.TButton",
            command=self._encrypt_selected_drive_sim
        ).pack(side="left", padx=5)

        ttk.Button(
            btn_frame,
            text="Refresh Drives",
            style="Alien.TButton",
            command=self._populate_drives
        ).pack(side="left", padx=5)

        status = ttk.Label(
            self,
            textvariable=self.status_var,
            style="Alien.TLabel"
        )
        status.pack(side="bottom", fill="x", pady=4)

        self._populate_drives()

    def _populate_drives(self):
        for item in self.drive_tree.get_children():
            self.drive_tree.delete(item)
        for root, label in list_windows_drives():
            self.drive_tree.insert("", tk.END, values=(root, label))

    def _handle_authorize(self):
        if self.lock_state.is_locked():
            AlienLockdownWindow(self.winfo_toplevel(), self.lock_state)
            self.status_var.set("SYSTEM LOCKED – NO INPUT ACCEPTED.")
            return

        pin = self.pin_var.get().strip()
        gly = self.glycine_var.get().strip()
        num = self.numeric_var.get().strip()

        if not pin or not gly or not num:
            self.lock_state.register_failure()
            remaining = MAX_FAILED_ATTEMPTS - self.lock_state.failed_attempts
            if self.lock_state.is_locked():
                AlienLockdownWindow(self.winfo_toplevel(), self.lock_state)
                self.status_var.set("SYSTEM LOCKED – NO INPUT ACCEPTED.")
                return
            self.status_var.set(f"Authorization failed. Remaining attempts: {max(remaining, 0)}")
            return

        selection = self.plugin_list.curselection()
        if selection:
            plugin_name = self.plugin_list.get(selection[0])
            ctx = {"pin": pin, "glycine": gly, "numeric": num}
            ctx = self.plugin_manager.apply_factor(plugin_name, ctx)

        self.status_var.set("Authorization successful. Alien systems online.")

    def _gen_pin(self):
        pin = "".join(secrets.choice(string.digits) for _ in range(6))
        self.pin_var.set(pin)
        self.status_var.set("Generated new PIN.")

    def _gen_glycine(self):
        key = secrets.token_hex(32)
        self.glycine_var.set(key)
        self.status_var.set("Generated new Glycine key.")

    def _gen_numeric(self):
        num = "".join(secrets.choice(string.digits) for _ in range(12))
        self.numeric_var.set(num)
        self.status_var.set("Generated new Numeric layer key.")

    def _encrypt_selected_drive_real(self):
        if self.lock_state.is_locked():
            AlienLockdownWindow(self.winfo_toplevel(), self.lock_state)
            self.status_var.set("SYSTEM LOCKED – NO INPUT ACCEPTED.")
            return

        sel = self.drive_tree.selection()
        if not sel:
            self.status_var.set("No drive selected.")
            return

        vals = self.drive_tree.item(sel[0])["values"]
        drive_root = vals[0]

        def status_cb(msg: str):
            self.status_var.set(msg)
            self.update_idletasks()

        try:
            encrypt_drive_contents(
                drive_root=drive_root,
                sound_path=None,
                voice_path=None,
                numbers=self.numeric_var.get(),
                glyph_seed=self.glycine_var.get() or generate_random_glyph_seed(),
                pin=self.pin_var.get() or generate_random_pin(),
                phrase="DominionDrive",
                kdf_mode="argon2id",
                status_callback=status_cb,
            )
            self.status_var.set(f"Drive {drive_root} encrypted into _mme_encrypted.")
        except Exception as exc:
            self.status_var.set(f"Failed to encrypt drive {drive_root}: {exc}")

    def _encrypt_selected_drive_sim(self):
        sel = self.drive_tree.selection()
        if not sel:
            self.status_var.set("No drive selected.")
            return
        vals = self.drive_tree.item(sel[0])["values"]
        drive_root = vals[0]
        self.status_var.set(f"[SIM] Encrypting drive {drive_root}…")
        self.after(500, lambda: self.status_var.set(f"[SIM] Drive {drive_root} encryption simulated."))


# ---------------------------------------------------------------------------
# Multimodal Encryption Panel (GUI) – refactored to embed in fusion app
# ---------------------------------------------------------------------------

class EncryptionPanel(ttk.Frame):
    def __init__(self, master):
        super().__init__(master, style="Alien.TFrame")
        self.input_file: Optional[str] = None
        self.output_file: Optional[str] = None
        self.sound_file: Optional[str] = None
        self.voice_file: Optional[str] = None
        self.kdf_mode = tk.StringVar(value="argon2id")
        self.drive_list: List[Tuple[str, str]] = []
        self.drive_var = tk.StringVar(value="")
        self.status_var = tk.StringVar(value="Ready.")
        self._apply_alien_theme()
        self._build_ui()
        self._refresh_drives()

    def _apply_alien_theme(self):
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Alien.TFrame", background="#050810")
        style.configure("Alien.TLabel", background="#050810", foreground="#00ffcc", font=("Segoe UI", 10))
        style.configure("Alien.Title.TLabel", background="#050810", foreground="#00ffcc", font=("Segoe UI", 18, "bold"))
        style.configure("Alien.TButton", background="#101520", foreground="#00ffcc", padding=6)
        style.configure("Alien.TLabelframe", background="#050810", foreground="#00ffcc")
        style.configure("Alien.TEntry", fieldbackground="#101520", foreground="#00ffcc")

    def _build_ui(self):
        outer = ttk.Frame(self, padding=12, style="Alien.TFrame")
        outer.pack(fill="both", expand=True)

        ttk.Label(
            outer,
            text="District 10 Multimodal Encryption Node",
            style="Alien.Title.TLabel",
        ).pack(anchor="w")
        ttk.Label(
            outer,
            text="Encrypt files and drives with multi-factor keys, alien glyph seeds, and hardened Dominion-grade crypto.",
            style="Alien.TLabel",
            wraplength=860,
        ).pack(anchor="w", pady=(2, 10))

        files = ttk.LabelFrame(outer, text="Settlement Files", padding=8, style="Alien.TLabelframe")
        files.pack(fill="x", pady=4)
        self.file_labels: Dict[str, ttk.Label] = {}
        rows = [
            ("input", "Input file (to encrypt/decrypt)", self.select_input),
            ("output", "Encrypted/decrypted output", self.select_output),
            ("sound", "Optional sound factor", self.select_sound),
            ("voice", "Optional voice factor", self.select_voice),
        ]
        for r, (key, label, command) in enumerate(rows):
            ttk.Button(files, text="Choose…", command=command, style="Alien.TButton").grid(
                row=r, column=0, padx=(0, 8), pady=3, sticky="w"
            )
            ttk.Label(files, text=label, style="Alien.TLabel").grid(row=r, column=1, sticky="w")
            lab = ttk.Label(files, text="Not selected", width=58, style="Alien.TLabel")
            lab.grid(row=r, column=2, sticky="ew", padx=4)
            self.file_labels[key] = lab
        files.columnconfigure(2, weight=1)

        factors = ttk.LabelFrame(outer, text="Key Factors (Alien Settlement)", padding=8, style="Alien.TLabelframe")
        factors.pack(fill="x", pady=4)

        self.numbers = self._entry_row_with_keygen(
            factors, 0, "Numeric layer (optional)", "", self.on_generate_numbers
        )
        self.glyph_seed = self._entry_row_with_keygen(
            factors, 1, "Glyph seed", "", self.on_generate_glyph_seed
        )
        self.pin = self._entry_row_with_keygen(
            factors, 2, "PIN/passphrase (8+ characters)", "", self.on_generate_pin, show="*"
        )
        self.phrase = self._entry_row(factors, 3, "Confirmation phrase", "")

        ttk.Label(factors, text="KDF mode", style="Alien.TLabel").grid(row=4, column=0, sticky="w", pady=3)
        kdf_box = ttk.Combobox(
            factors,
            textvariable=self.kdf_mode,
            values=["argon2id", "pbkdf2"],
            state="readonly",
        )
        kdf_box.grid(row=4, column=1, sticky="ew", pady=3, padx=(8, 0))
        factors.columnconfigure(1, weight=1)

        drive_frame = ttk.LabelFrame(outer, text="Drive Encryption (A–Z + USB)", padding=8, style="Alien.TLabelframe")
        drive_frame.pack(fill="x", pady=4)

        ttk.Label(drive_frame, text="Available drives", style="Alien.TLabel").grid(row=0, column=0, sticky="w", pady=3)
        self.drive_combo = ttk.Combobox(
            drive_frame,
            textvariable=self.drive_var,
            state="readonly",
            width=40,
        )
        self.drive_combo.grid(row=0, column=1, sticky="ew", padx=8, pady=3)
        drive_frame.columnconfigure(1, weight=1)

        ttk.Button(
            drive_frame,
            text="Encrypt Drive Contents",
            style="Alien.TButton",
            command=self.on_encrypt_drive,
        ).grid(row=0, column=2, padx=8, pady=3)

        action_frame = ttk.Frame(outer, style="Alien.TFrame")
        action_frame.pack(fill="x", pady=8)

        ttk.Button(
            action_frame,
            text="Encrypt File",
            style="Alien.TButton",
            command=self.on_encrypt_file,
        ).pack(side="left", padx=4)

        ttk.Button(
            action_frame,
            text="Decrypt File",
            style="Alien.TButton",
            command=self.on_decrypt_file,
        ).pack(side="left", padx=4)

        ttk.Button(
            action_frame,
            text="Show Glyph Timeline",
            style="Alien.TButton",
            command=self.on_show_glyph_timeline,
        ).pack(side="left", padx=4)

        status = ttk.Label(
            outer,
            textvariable=self.status_var,
            style="Alien.TLabel",
        )
        status.pack(fill="x", pady=4)

    def _entry_row(self, parent, row: int, label: str, default: str, show: Optional[str] = None) -> tk.StringVar:
        ttk.Label(parent, text=label, style="Alien.TLabel").grid(row=row, column=0, sticky="w", pady=3)
        var = tk.StringVar(value=default)
        entry = ttk.Entry(parent, textvariable=var, show=show if show else "")
        entry.grid(row=row, column=1, sticky="ew", padx=(8, 0), pady=3)
        parent.columnconfigure(1, weight=1)
        return var

    def _entry_row_with_keygen(
        self,
        parent,
        row: int,
        label: str,
        default: str,
        gen_callback: Callable[[], None],
        show: Optional[str] = None,
    ) -> tk.StringVar:
        var = self._entry_row(parent, row, label, default, show=show)
        ttk.Button(
            parent,
            text="Generate",
            style="Alien.TButton",
            command=gen_callback,
        ).grid(row=row, column=2, padx=8, pady=3, sticky="w")
        return var

    def _refresh_drives(self):
        self.drive_list = list_windows_drives()
        display = [f"{root} ({label})" for root, label in self.drive_list]
        self.drive_combo["values"] = display
        if display:
            self.drive_combo.current(0)

    def select_input(self):
        path = filedialog.askopenfilename(title="Select input file")
        if path:
            self.input_file = path
            self.file_labels["input"].config(text=path)

    def select_output(self):
        path = filedialog.asksaveasfilename(title="Select output file", defaultextension=".mme")
        if path:
            self.output_file = path
            self.file_labels["output"].config(text=path)

    def select_sound(self):
        path = filedialog.askopenfilename(title="Select sound factor file")
        if path:
            self.sound_file = path
            self.file_labels["sound"].config(text=path)

    def select_voice(self):
        path = filedialog.askopenfilename(title="Select voice factor file")
        if path:
            self.voice_file = path
            self.file_labels["voice"].config(text=path)

    def on_generate_numbers(self):
        self.numbers.set(generate_random_numeric_layer())
        self.status_var.set("Generated numeric layer.")

    def on_generate_glyph_seed(self):
        self.glyph_seed.set(generate_random_glyph_seed())
        self.status_var.set("Generated glyph seed.")

    def on_generate_pin(self):
        self.pin.set(generate_random_pin())
        self.status_var.set("Generated PIN/passphrase.")

    def _collect_key_params(self) -> Tuple[str, str, str, str]:
        return (
            self.pin.get().strip(),
            self.phrase.get().strip(),
            self.numbers.get().strip(),
            self.glyph_seed.get().strip(),
        )

    def on_encrypt_file(self):
        try:
            if not self.input_file:
                raise ValueError("Select an input file.")
            if not self.output_file:
                raise ValueError("Select an output file.")
            pin, phrase, numbers, glyph_seed = self._collect_key_params()
            encrypt_file(
                input_path=self.input_file,
                output_path=self.output_file,
                sound_path=self.sound_file,
                voice_path=self.voice_file,
                numbers=numbers,
                glyph_seed=glyph_seed,
                pin=pin,
                phrase=phrase,
                kdf_mode=self.kdf_mode.get(),
            )
            self.status_var.set("File encrypted successfully.")
        except Exception as exc:
            self.status_var.set(f"Encrypt failed: {exc}")
            traceback.print_exc()

    def on_decrypt_file(self):
        try:
            if not self.input_file:
                raise ValueError("Select an encrypted input file (.mme).")
            if not self.output_file:
                raise ValueError("Select an output file.")
            pin, phrase, numbers, glyph_seed = self._collect_key_params()
            meta = decrypt_file(
                input_path=self.input_file,
                output_path=self.output_file,
                sound_path=self.sound_file,
                voice_path=self.voice_file,
                numbers=numbers,
                glyph_seed=glyph_seed,
                pin=pin,
                phrase=phrase,
            )
            self.status_var.set(f"File decrypted. Original: {meta.get('original_filename', '?')}")
        except Exception as exc:
            self.status_var.set(f"Decrypt failed: {exc}")
            traceback.print_exc()

    def on_encrypt_drive(self):
        if not self.drive_list:
            self.status_var.set("No drives available.")
            return
        idx = self.drive_combo.current()
        if idx < 0 or idx >= len(self.drive_list):
            self.status_var.set("Select a drive.")
            return
        drive_root, label = self.drive_list[idx]
        pin, phrase, numbers, glyph_seed = self._collect_key_params()
        if not phrase:
            phrase = "DriveBulk"
        if not glyph_seed:
            glyph_seed = generate_random_glyph_seed()

        def status_cb(msg: str):
            self.status_var.set(msg)
            self.update_idletasks()

        try:
            encrypt_drive_contents(
                drive_root=drive_root,
                sound_path=self.sound_file,
                voice_path=self.voice_file,
                numbers=numbers,
                glyph_seed=glyph_seed,
                pin=pin,
                phrase=phrase,
                kdf_mode=self.kdf_mode.get(),
                status_callback=status_cb,
            )
            self.status_var.set(f"Drive {drive_root} encrypted into _mme_encrypted.")
        except Exception as exc:
            self.status_var.set(f"Drive encryption failed: {exc}")

    def on_show_glyph_timeline(self):
        glyph_seed = self.glyph_seed.get().strip()
        if not glyph_seed:
            glyph_seed = generate_random_glyph_seed()
            self.glyph_seed.set(glyph_seed)
        stream = generate_hieroglyph_stream(glyph_seed)
        show_hieroglyph_timeline(stream)


# ---------------------------------------------------------------------------
# Fusion App – DominionDeck Command Center
# ---------------------------------------------------------------------------

class DominionDeckApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(APP_NAME)
        self.geometry("1200x800")
        self.configure(bg="#050308")

        self.style = ttk.Style(self)
        self._setup_style()

        self.lock_state = LockoutState(LOCK_STATE_FILE)
        self.plugin_manager = FactorPluginManager(Path("plugins"))

        notebook = ttk.Notebook(self)
        notebook.pack(expand=True, fill="both")

        self.encryption_panel = EncryptionPanel(notebook)
        self.security_panel = DominionSecurityPanel(notebook, self.lock_state, self.plugin_manager)

        notebook.add(self.encryption_panel, text="Multimodal Encryption")
        notebook.add(self.security_panel, text="Alien Security Mode")

        if self.lock_state.is_locked():
            AlienLockdownWindow(self, self.lock_state)

    def _setup_style(self):
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        self.style.configure("Alien.TFrame", background="#050308")
        self.style.configure(
            "Alien.TButton",
            background="#111122",
            foreground="#39ff14",
            font=("Consolas", 11, "bold")
        )
        self.style.map(
            "Alien.TButton",
            background=[("active", "#222244")]
        )
        self.style.configure(
            "Alien.TLabel",
            background="#050308",
            foreground="#00e5ff",
            font=("Consolas", 11)
        )
        self.style.configure(
            "Alien.Title.TLabel",
            background="#050308",
            foreground="#00e5ff",
            font=("Consolas", 18, "bold")
        )


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main():
    app = DominionDeckApp()
    app.mainloop()


if __name__ == "__main__":
    main()
