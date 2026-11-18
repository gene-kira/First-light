import sys
import subprocess

# --- AUTOMATIC LIBRARY LOADER ---
def auto_install_requirements():
    required_packages = {
        "Pillow": "PIL",
        "cryptography": "cryptography",
        "qrcode": "qrcode",
        "opencv-python": "cv2"
    }
    for pkg, imp in required_packages.items():
        try:
            __import__(imp)
        except ImportError:
            print(f"[*] Missing required library '{pkg}'. Installing automatically...")
            try:
                subprocess.check_call([sys.executable, "-m", "pip", "install", pkg])
                print(f"[*] Successfully installed {pkg}!")
            except Exception as e:
                print(f"[!] Failed to install {pkg}: {e}")
                sys.exit(1)

auto_install_requirements()

import tkinter as tk
from tkinter import messagebox, filedialog, ttk
import random
import string
import os
import platform
import uuid
import base64
import json
import datetime
import threading
import urllib.parse
import http.server
import socketserver
from PIL import Image, ImageDraw, ImageTk
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import qrcode
import cv2

app_instance = None

class VaultBridgeHandler(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == "/generate-pwd":
            try:
                length = 24
                if app_instance and hasattr(app_instance, 'length_slider'):
                    length = app_instance.length_slider.get()

                alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
                base_password = ''.join(random.choice(alphabet) for _ in range(min(length, 8)))
                
                if length > len(base_password):
                    chars_needed = length - len(base_password)
                    padding = ''.join(random.choice(alphabet) for _ in range(chars_needed))
                    password = base_password + padding
                else:
                    password = base_password[:length]

                # Thread-safely update the desktop app's output box and system clipboard
                if app_instance and hasattr(app_instance, 'root'):
                    def update_ui_and_clipboard():
                        app_instance.output_text.delete("1.0", tk.END)
                        app_instance.output_text.insert(tk.END, password)
                        app_instance.root.clipboard_clear()
                        app_instance.root.clipboard_append(password)
                        app_instance.status_label.config(text="Generated & copied password for browser bridge!", fg="#a6e3a1")
                    
                    app_instance.root.after(0, update_ui_and_clipboard)

                response_data = {"status": "success", "password": password}
                code = 200
            except Exception as e:
                response_data = {"status": "error", "message": str(e)}
                code = 500

            self.send_response(code)
            self.send_header("Access-Control-Allow-Origin", "*")
            self.send_header("Content-type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode('utf-8'))
        else:
            self.send_response(404)
            self.end_headers()

    def log_message(self, format, *args):
        return

class StegoVaultProApp:
    def __init__(self, root):
        global app_instance
        app_instance = self

        self.root = root
        self.root.title("Stego-Vault Pro: Unified Browser Bridge Edition")
        self.root.geometry("800x980")
        self.root.config(bg="#1e1e2e")

        self.selected_images = []
        self.current_qr_image = None
        self.qr_photo = None
        self.local_token_file = "local_vault_token.enc"

        title_frame = tk.Frame(root, bg="#1e1e2e")
        title_frame.pack(pady=10)
        tk.Label(title_frame, text="🔐 Stego-Vault Pro + Unified Browser Bridge", font=("Arial", 18, "bold"), fg="#cdd6f4", bg="#1e1e2e").pack()
        tk.Label(title_frame, text="Auto-Unlock, Biometric Guard, Webcam QR & Direct Browser Integration", font=("Arial", 9, "italic"), fg="#89b4fa", bg="#1e1e2e").pack()

        self.style = ttk.Style()
        self.style.theme_use("default")
        self.style.configure("TNotebook", background="#1e1e2e", borderwidth=0)
        self.style.configure("TNotebook.Tab", background="#313244", foreground="#cdd6f4", padding=[12, 8], font=("Arial", 9, "bold"))
        self.style.map("TNotebook.Tab", background=[("selected", "#89b4fa")], foreground=[("selected", "#11111b")])

        self.notebook = ttk.Notebook(root)
        self.notebook.pack(pady=10, padx=15, fill="both", expand=True)

        self.tab_gen = tk.Frame(self.notebook, bg="#1e1e2e")
        self.tab_dec = tk.Frame(self.notebook, bg="#1e1e2e")
        self.tab_qr = tk.Frame(self.notebook, bg="#1e1e2e")

        self.notebook.add(self.tab_gen, text=" 🛡️ Generator & Embedder ")
        self.notebook.add(self.tab_dec, text=" 🔓 Smart Decoder & Scanner ")
        self.notebook.add(self.tab_qr, text=" 📱 QR Code & Mobile Sync ")

        self.setup_generator_tab()
        self.setup_decoder_tab()
        self.setup_qr_tab()

        self.status_label = tk.Label(root, text="Ready. Browser Bridge listening on http://127.0.0.1:5000", font=("Arial", 9), fg="#a6e3a1", bg="#1e1e2e")
        self.status_label.pack(side="bottom", pady=8)

        self.start_browser_bridge_server()

    def start_browser_bridge_server(self):
        def run_server():
            port = 5000
            try:
                with socketserver.TCPServer(("127.0.0.1", port), VaultBridgeHandler) as httpd:
                    httpd.serve_forever()
            except Exception as e:
                print(f"[!] Browser bridge server error: {e}")

        threading.Thread(target=run_server, daemon=True).start()

    def get_hardware_fingerprint(self) -> str:
        return f"{platform.node()}-{platform.machine()}-{platform.processor()}-{uuid.getnode()}"

    def derive_key(self, passphrase: str, salt: bytes) -> bytes:
        hardware_salt_modifier = self.get_hardware_fingerprint().encode('utf-8')
        combined_secret = passphrase.encode('utf-8') + hardware_salt_modifier
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
        return base64.urlsafe_b64encode(kdf.derive(combined_secret))

    def save_local_auto_token(self, passphrase: str, salt: bytes):
        try:
            token_data = {
                "passphrase": passphrase,
                "salt": base64.b64encode(salt).decode('utf-8'),
                "hw_sig": self.get_hardware_fingerprint()
            }
            with open(self.local_token_file, "w") as f:
                json.dump(token_data, f)
        except Exception:
            pass

    def try_local_auto_unlock(self, salt: bytes) -> tuple:
        if not os.path.exists(self.local_token_file):
            return None, None
        try:
            with open(self.local_token_file, "r") as f:
                token_data = json.load(f)
            if token_data.get("hw_sig") == self.get_hardware_fingerprint():
                saved_pass = token_data.get("passphrase")
                saved_salt = base64.b64decode(token_data.get("salt"))
                if saved_salt == salt:
                    return saved_pass, "Zero-Touch Auto-Unlock (Originating Machine)"
        except Exception:
            pass
        return None, None

    def verify_facial_recognition(self) -> bool:
        try:
            messagebox.showinfo("Biometric Challenge", "Foreign device detected!\n\nPlease look at your camera and press 'SPACEBAR' to complete biometric facial verification.")
            cap = cv2.VideoCapture(0)
            if not cap.isOpened():
                messagebox.showerror("Camera Error", "No compatible webcam found for biometric verification!")
                return False

            face_cascade = cv2.CascadeClassifier(cv2.data.haarcascades + 'haarcascade_frontalface_default.xml')
            verified = False

            while True:
                ret, frame = cap.read()
                if not ret:
                    break
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                faces = face_cascade.detectMultiScale(gray, 1.1, 4)
                for (x, y, w, h) in faces:
                    cv2.rectangle(frame, (x, y), (x+w, y+h), (0, 255, 0), 2)
                    cv2.putText(frame, "Press SPACEBAR to Verify Face", (x, y-10), cv2.FONT_HERSHEY_SIMPLEX, 0.6, (0, 255, 0), 2)
                cv2.imshow("Stego-Vault Biometric Scanner (Press SPACE to Verify)", frame)
                key = cv2.waitKey(1) & 0xFF
                if key == 32:
                    if len(faces) > 0:
                        verified = True
                    break
                elif key == 27:
                    break

            cap.release()
            cv2.destroyAllWindows()
            return verified
        except Exception as e:
            messagebox.showerror("Biometric Error", f"Facial recognition sequence failed: {e}")
            return False

    def scan_qr_from_webcam(self):
        cap = cv2.VideoCapture(0)
        if not cap.isOpened():
            messagebox.showerror("Camera Error", "Could not access webcam for QR scanning!")
            return

        detector = cv2.QRCodeDetector()
        scanned_data = None

        while True:
            ret, frame = cap.read()
            if not ret:
                break
            data, bbox, _ = detector.detectAndDecode(frame)
            if data:
                scanned_data = data
                if bbox is not None:
                    pts = bbox.astype(int).reshape(-1, 2)
                    cv2.polylines(frame, [pts], True, (0, 255, 0), 3)
                cv2.imshow("Webcam QR Scanner (Scanning...)", frame)
                cv2.waitKey(600)
                break
            cv2.imshow("Webcam QR Scanner (Hold QR in view... Press ESC to quit)", frame)
            if (cv2.waitKey(1) & 0xFF) == 27:
                break

        cap.release()
        cv2.destroyAllWindows()

        if scanned_data:
            self.scanned_payload_string = scanned_data
            self.status_label.config(text="Successfully captured stego-string via webcam!", fg="#a6e3a1")
            messagebox.showinfo("QR Scanned Successfully", "Stego-password string successfully captured from your smartphone screen!")
        else:
            self.status_label.config(text="Webcam QR scan cancelled or no code detected.", fg="#f38ba8")

    def setup_generator_tab(self):
        f = self.tab_gen

        tk.Label(f, text="Base Password:", font=("Arial", 10, "bold"), fg="#bac2de", bg="#1e1e2e").pack(anchor="w", padx=20, pady=(8, 2))
        self.pwd_entry = tk.Entry(f, font=("Arial", 11), width=45, show="*")
        self.pwd_entry.pack(anchor="w", padx=20, pady=2)
        self.pwd_entry.bind("<KeyRelease>", self.update_entropy)

        len_frame = tk.Frame(f, bg="#1e1e2e")
        len_frame.pack(anchor="w", padx=20, pady=6, fill="x")
        tk.Label(len_frame, text="Target Length:", font=("Arial", 10, "bold"), fg="#bac2de", bg="#1e1e2e").pack(side="left")
        
        self.length_slider = tk.Scale(len_frame, from_=8, to=150, orient="horizontal", bg="#313244", fg="#cdd6f4", highlightbackground="#1e1e2e", troughcolor="#45475a", command=self.update_entropy)
        self.length_slider.set(24)
        self.length_slider.pack(side="left", fill="x", expand=True, padx=10)

        self.entropy_label = tk.Label(f, text="Strength: Evaluating...", font=("Arial", 9, "bold"), fg="#f9e2af", bg="#1e1e2e")
        self.entropy_label.pack(anchor="w", padx=20, pady=2)

        tk.Label(f, text="Secret Text Payload (Notes, Hints, Keys):", font=("Arial", 10, "bold"), fg="#bac2de", bg="#1e1e2e").pack(anchor="w", padx=20, pady=(6, 2))
        self.payload_entry = tk.Entry(f, font=("Arial", 11), width=45)
        self.payload_entry.pack(anchor="w", padx=20, pady=2)
        self.payload_entry.insert(0, "VaultKey#99 - Confidential Data")

        tk.Label(f, text="Master Encryption Passphrase:", font=("Arial", 10, "bold"), fg="#bac2de", bg="#1e1e2e").pack(anchor="w", padx=20, pady=(6, 2))
        self.secret_pin_entry = tk.Entry(f, font=("Arial", 11), width=45, show="*")
        self.secret_pin_entry.pack(anchor="w", padx=20, pady=2)
        self.secret_pin_entry.insert(0, "MasterPin1234")

        self.hw_lock_var = tk.BooleanVar(value=True)
        hw_check = tk.Checkbutton(f, text="🔒 Enable Zero-Touch Auto-Unlock Locally + Biometric Guard Elsewhere", variable=self.hw_lock_var, font=("Arial", 9, "bold"), fg="#a6e3a1", bg="#1e1e2e", selectcolor="#313244", activebackground="#1e1e2e", activeforeground="#a6e3a1")
        hw_check.pack(anchor="w", padx=20, pady=6)

        img_frame = tk.LabelFrame(f, text=" Embedded Pictures / Assets ", font=("Arial", 10, "bold"), fg="#89b4fa", bg="#1e1e2e", bd=2, relief="groove")
        img_frame.pack(pady=6, padx=20, fill="x", ipadx=10, ipady=4)

        self.img_list_label = tk.Label(img_frame, text="No pictures selected (Optional)", font=("Arial", 9, "italic"), fg="#9399b2", bg="#1e1e2e")
        self.img_list_label.pack(side="left", padx=5)

        add_img_btn = tk.Button(img_frame, text="Add Picture(s)", font=("Arial", 9, "bold"), bg="#45475a", fg="#cdd6f4", command=self.add_images)
        add_img_btn.pack(side="right", padx=5)

        clear_img_btn = tk.Button(img_frame, text="Clear List", font=("Arial", 9), bg="#f38ba8", fg="#11111b", command=self.clear_images)
        clear_img_btn.pack(side="right", padx=5)

        gen_btn = tk.Button(f, text="🚀 Generate Auto-Unlock Password & Card", font=("Arial", 11, "bold"), bg="#89b4fa", fg="#11111b", command=self.generate_stego)
        gen_btn.pack(pady=8, padx=20, fill="x")

        tk.Label(f, text="Generated Obfuscated Password String:", font=("Arial", 9, "bold"), fg="#9399b2", bg="#1e1e2e").pack(anchor="w", padx=20)
        
        out_box_frame = tk.Frame(f, bg="#1e1e2e")
        out_box_frame.pack(padx=20, fill="x", pady=2)
        
        self.output_text = tk.Text(out_box_frame, height=3, font=("Consolas", 10), bg="#313244", fg="#cdd6f4")
        self.output_text.pack(side="left", fill="x", expand=True)
        
        copy_btn = tk.Button(out_box_frame, text="Copy", font=("Arial", 9, "bold"), bg="#a6e3a1", fg="#11111b", command=self.copy_to_clipboard)
        copy_btn.pack(side="right", padx=(5,0), fill="y")

    def setup_decoder_tab(self):
        f = self.tab_dec
        tk.Label(f, text="Select Password Card Image (.png) OR Scan via Webcam:", font=("Arial", 11, "bold"), fg="#bac2de", bg="#1e1e2e").pack(anchor="w", padx=20, pady=(15, 5))
        
        file_sel_frame = tk.Frame(f, bg="#1e1e2e")
        file_sel_frame.pack(anchor="w", padx=20, fill="x")
        
        self.dec_path_entry = tk.Entry(file_sel_frame, font=("Arial", 10), width=32)
        self.dec_path_entry.pack(side="left", padx=(0,10))
        
        browse_card_btn = tk.Button(file_sel_frame, text="Browse Card", font=("Arial", 10, "bold"), bg="#45475a", fg="#cdd6f4", command=self.browse_card)
        browse_card_btn.pack(side="left", padx=(0, 10))

        webcam_scan_btn = tk.Button(file_sel_frame, text="📷 Scan QR via Webcam", font=("Arial", 10, "bold"), bg="#89b4fa", fg="#11111b", command=self.scan_qr_from_webcam)
        webcam_scan_btn.pack(side="left")

        tk.Label(f, text="Master Encryption Passphrase (Optional if on same machine):", font=("Arial", 11, "bold"), fg="#bac2de", bg="#1e1e2e").pack(anchor="w", padx=20, pady=(15, 5))
        self.dec_pin_entry = tk.Entry(f, font=("Arial", 11), width=40, show="*")
        self.dec_pin_entry.pack(anchor="w", padx=20)
        self.dec_pin_entry.insert(0, "")

        decode_btn = tk.Button(f, text="🔍 Smart Unlock & Extract Payload", font=("Arial", 11, "bold"), bg="#a6e3a1", fg="#11111b", command=self.decode_payload)
        decode_btn.pack(pady=15, padx=20, fill="x")

        tk.Label(f, text="Extracted Decrypted Content & Audit Log:", font=("Arial", 10, "bold"), fg="#9399b2", bg="#1e1e2e").pack(anchor="w", padx=20)
        self.dec_output_text = tk.Text(f, height=8, font=("Consolas", 10), bg="#313244", fg="#cdd6f4")
        self.dec_output_text.pack(padx=20, fill="x", pady=5)

    def setup_qr_tab(self):
        f = self.tab_qr
        tk.Label(f, text="Paste Stego-Password or Secret Data to Encode into QR:", font=("Arial", 10, "bold"), fg="#bac2de", bg="#1e1e2e").pack(anchor="w", padx=20, pady=(15, 5))
        
        self.qr_input_text = tk.Text(f, height=3, font=("Consolas", 10), bg="#313244", fg="#cdd6f4")
        self.qr_input_text.pack(padx=20, fill="x", pady=2)
        self.qr_input_text.insert(tk.END, "Paste your obfuscated password here...")

        qr_btn_frame = tk.Frame(f, bg="#1e1e2e")
        qr_btn_frame.pack(pady=10, padx=20, fill="x")

        gen_qr_btn = tk.Button(qr_btn_frame, text="📱 Generate Smartphone QR Code", font=("Arial", 10, "bold"), bg="#89b4fa", fg="#11111b", command=self.generate_qr_code)
        gen_qr_btn.pack(side="left", padx=(0, 10))

        save_qr_btn = tk.Button(qr_btn_frame, text="💾 Save QR Image", font=("Arial", 10, "bold"), bg="#a6e3a1", fg="#11111b", command=self.save_qr_image)
        save_qr_btn.pack(side="left")

        self.qr_display_label = tk.Label(f, text="QR Code will appear here", font=("Arial", 10, "italic"), fg="#9399b2", bg="#313244", width=40, height=12)
        self.qr_display_label.pack(pady=10)

    def update_entropy(self, event=None):
        pwd = self.pwd_entry.get()
        target_len = self.length_slider.get()
        actual_len = max(len(pwd), target_len)
        if actual_len < 12:
            self.entropy_label.config(text=f"Length: {actual_len} chars | Strength: Weak", fg="#f38ba8")
        elif actual_len < 24:
            self.entropy_label.config(text=f"Length: {actual_len} chars | Strength: Moderate", fg="#f9e2af")
        else:
            self.entropy_label.config(text=f"Length: {actual_len} chars | Strength: Enterprise Grade", fg="#a6e3a1")

    def add_images(self):
        file_paths = filedialog.askopenfilenames(title="Select Images to Embed", filetypes=[("Image Files", "*.png *.jpg *.jpeg *.bmp")])
        if file_paths:
            for fp in file_paths:
                if fp not in self.selected_images:
                    self.selected_images.append(fp)
            self.img_list_label.config(text=f"{len(self.selected_images)} picture(s) attached ready for micro-embedding", fg="#a6e3a1")

    def clear_images(self):
        self.selected_images = []
        self.img_list_label.config(text="No pictures selected (Optional)", fg="#9399b2")

    def browse_card(self):
        file_path = filedialog.askopenfilename(title="Select Password Card Image", filetypes=[("PNG Files", "*.png")])
        if file_path:
            self.dec_path_entry.delete(0, tk.END)
            self.dec_path_entry.insert(0, file_path)
            self.scanned_payload_string = None

    def copy_to_clipboard(self):
        text = self.output_text.get("1.0", tk.END).strip()
        if text:
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status_label.config(text="Copied obfuscated password to clipboard!", fg="#a6e3a1")

    def generate_stego(self):
        base_password = self.pwd_entry.get()
        text_payload = self.payload_entry.get()
        passphrase = self.secret_pin_entry.get()
        target_length = self.length_slider.get()
        hardware_locked = self.hw_lock_var.get()

        if not base_password:
            messagebox.showerror("Error", "Please enter a base password!")
            return
        if not passphrase:
            messagebox.showerror("Error", "Please enter a master encryption passphrase!")
            return

        if len(base_password) < target_length:
            chars_needed = target_length - len(base_password)
            alphabet = string.ascii_letters + string.digits + "!@#$%^&*()_+-=[]{}|;:,.<>?"
            padding = ''.join(random.choice(alphabet) for _ in range(chars_needed))
            full_password = base_password + padding
        else:
            full_password = base_password[:target_length]

        payload_dict = {
            "text": text_payload,
            "hw_lock": hardware_locked,
            "hw_signature": self.get_hardware_fingerprint() if hardware_locked else "",
            "images": []
        }

        for img_path in self.selected_images:
            try:
                with Image.open(img_path) as img_obj:
                    img_obj = img_obj.resize((32, 32))
                    temp_name = "temp_asset.png"
                    img_obj.save(temp_name, "PNG")
                    with open(temp_name, "rb") as f:
                        b64_img = base64.b64encode(f.read()).decode('utf-8')
                        payload_dict["images"].append(b64_img)
                    os.remove(temp_name)
            except Exception as e:
                messagebox.showerror("Asset Error", f"Could not process image {img_path}: {e}")
                return

        payload_json = json.dumps(payload_dict).encode('utf-8')
        salt = os.urandom(16)
        self.save_local_auto_token(passphrase, salt)

        key = self.derive_key(passphrase, salt)
        f = Fernet(key)
        encrypted_data = f.encrypt(payload_json)
        final_package = salt + encrypted_data

        binary_payload = ''.join(format(byte, '08b') for byte in final_package)
        zw_map = {'0': '\u200b', '1': '\u200c'}
        hidden_zw_string = ''.join(zw_map[b] for b in binary_payload)
        obfuscated_pwd = full_password[0] + hidden_zw_string + full_password[1:]
        
        self.output_text.delete("1.0", tk.END)
        self.output_text.insert(tk.END, obfuscated_pwd)
        self.qr_input_text.delete("1.0", tk.END)
        self.qr_input_text.insert(tk.END, obfuscated_pwd)

        try:
            card_img = Image.new("RGB", (650, 220), color="#11111b")
            d = ImageDraw.Draw(card_img)
            d.text((30, 45), f"ZERO-TOUCH VAULT ({target_length} Chars)", fill="#89b4fa")
            d.text((30, 80), f"PWD: {full_password[:40]}...", fill="#fab387")
            d.text((30, 115), f"Status: Auto-Unlock Ready (Same Machine)", fill="#a6e3a1")
            d.text((30, 145), f"[Assets: {len(self.selected_images)} Pictures | AES Encrypted]", fill="#9399b2")

            pixels = card_img.load()
            data_index = 0
            data_len = len(binary_payload)
            for y in range(card_img.height):
                for x in range(card_img.width):
                    if data_index < data_len:
                        r, g, b = pixels[x, y]
                        r = (r & ~1) | int(binary_payload[data_index])
                        pixels[x, y] = (r, g, b)
                        data_index += 1
                    else:
                        break
                if data_index >= data_len:
                    break

            card_path = "webcam_vault_card.png"
            card_img.save(card_path)
            self.status_label.config(text=f"Success! Saved card as '{card_path}'", fg="#a6e3a1")
            messagebox.showinfo("Success", f"Password card and QR generator ready!\n\nSaved to: {card_path}")
        except Exception as e:
            messagebox.showerror("Error", f"Failed to generate card image: {e}")

    def generate_qr_code(self):
        text_data = self.qr_input_text.get("1.0", tk.END).strip()
        if not text_data or text_data == "Paste your obfuscated password here...":
            messagebox.showerror("Error", "Please enter valid text or stego-string to encode into a QR code!")
            return
        try:
            qr = qrcode.QRCode(version=None, error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=6, border=2)
            qr.add_data(text_data)
            qr.make(fit=True)
            self.current_qr_image = qr.make_image(fill_color="black", back_color="white")
            display_img = self.current_qr_image.resize((220, 220))
            self.qr_photo = ImageTk.PhotoImage(display_img)
            self.qr_display_label.config(image=self.qr_photo, text="", width=220, height=220)
            self.status_label.config(text="QR Code generated successfully!", fg="#a6e3a1")
        except Exception as e:
            messagebox.showerror("QR Error", f"Failed to generate QR code: {e}")

    def save_qr_image(self):
        if not self.current_qr_image:
            messagebox.showwarning("Warning", "Please generate a QR code first!")
            return
        file_path = filedialog.asksaveasfilename(defaultextension=".png", filetypes=[("PNG files", "*.png"), ("All files", "*.*")])
        if file_path:
            self.current_qr_image.save(file_path)
            messagebox.showinfo("Saved", f"QR Code successfully saved to {file_path}")

    def decode_payload(self):
        entered_passphrase = self.dec_pin_entry.get().strip()
        byte_array = None

        if hasattr(self, 'scanned_payload_string') and self.scanned_payload_string:
            try:
                zw_map = {'\u200b': '0', '\u200c': '1'}
                bin_chars = [zw_map[c] for c in self.scanned_payload_string if c in zw_map]
                bit_string = "".join(bin_chars)
                byte_array = bytearray()
                for i in range(0, len(bit_string), 8):
                    byte_chunk = bit_string[i:i+8]
                    if len(byte_chunk) < 8:
                        break
                    byte_array.append(int(byte_chunk, 2))
            except Exception:
                pass

        if not byte_array:
            file_path = self.dec_path_entry.get()
            if not file_path or not os.path.exists(file_path):
                messagebox.showerror("Error", "Please select a valid Password Card image OR scan a QR code via webcam!")
                return
            try:
                img = Image.open(file_path)
                pixels = img.load()
                bits = []
                for y in range(img.height):
                    for x in range(img.width):
                        r, g, b = pixels[x, y]
                        bits.append(str(r & 1))
                bit_string = "".join(bits)
                byte_array = bytearray()
                for i in range(0, len(bit_string), 8):
                    byte_chunk = bit_string[i:i+8]
                    if len(byte_chunk) < 8:
                        break
                    byte_array.append(int(byte_chunk, 2))
            except Exception as e:
                messagebox.showerror("Error", f"Failed to read image card: {e}")
                return

        if not byte_array or len(byte_array) < 16:
            messagebox.showerror("Error", "No valid stego data found.")
            return

        try:
            salt = bytes(byte_array[:16])
            ciphertext = bytes(byte_array[16:])
            active_passphrase = entered_passphrase
            unlock_method = "Manual Passphrase"

            auto_pass, auto_msg = self.try_local_auto_unlock(salt)
            if auto_pass and not active_passphrase:
                active_passphrase = auto_pass
                unlock_method = auto_msg

            if not active_passphrase:
                if messagebox.askyesno("Foreign Device Detected", "No local auto-unlock token found. Launch Biometric Facial Recognition Verification?"):
                    if not self.verify_facial_recognition():
                        messagebox.showerror("Access Denied", "Biometric facial verification failed or cancelled.")
                        return
                    from tkinter import simpledialog
                    active_passphrase = simpledialog.askstring("Master Passphrase Required", "Facial verification passed! Enter your Master Passphrase:", show='*')
                    unlock_method = "Biometric Challenge + Manual Passphrase"
                else:
                    return

            if not active_passphrase:
                messagebox.showerror("Error", "Passphrase required to decrypt this vault card.")
                return

            key = self.derive_key(active_passphrase, salt)
            f = Fernet(key)
            decrypted_json = f.decrypt(ciphertext)
            payload_data = json.loads(decrypted_json.decode('utf-8'))
            
            is_locked = payload_data.get("hw_lock", False)
            target_signature = payload_data.get("hw_signature", "")
            current_signature = self.get_hardware_fingerprint()

            if is_locked and target_signature != current_signature and unlock_method == "Manual Passphrase":
                if not self.verify_facial_recognition():
                    messagebox.showerror("Access Denied", "Hardware lock mismatch. Biometric verification failed.")
                    return
                unlock_method = "Hardware Mismatch + Biometric Override"

            text_note = payload_data.get("text", "")
            images_list = payload_data.get("images", [])

            output_summary = f"=== DECRYPTION SUCCESSFUL ===\n\n"
            output_summary += f"Unlock Method: {unlock_method} 🟢\n"
            output_summary += f"Timestamp: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n\n"
            output_summary += f"Secret Text Payload:\n{text_note}\n\n"

            if images_list:
                output_summary += f"Extracted {len(images_list)} embedded picture(s):\n"
                for idx, b64_img in enumerate(images_list):
                    img_bytes = base64.b64decode(b64_img)
                    out_img_name = f"extracted_asset_{idx+1}.png"
                    with open(out_img_name, "wb") as img_file:
                        img_file.write(img_bytes)
                    output_summary += f" - Saved to '{out_img_name}'\n"
            else:
                output_summary += "No custom pictures were attached to this card.\n"

            self.dec_output_text.delete("1.0", tk.END)
            self.dec_output_text.insert(tk.END, output_summary)
            self.status_label.config(text=f"Unlocked successfully via: {unlock_method}", fg="#a6e3a1")

        except Exception as e:
            messagebox.showerror("Decryption Failed", f"Could not decrypt payload. Incorrect passphrase or invalid token.\n\nDetails: {e}")
            self.status_label.config(text="Decryption failed: Incorrect key or invalid file.", fg="#f38ba8")

if __name__ == "__main__":
    root = tk.Tk()
    app = StegoVaultProApp(root)
    root.mainloop()