#!/usr/bin/env python3
"""
LockIt Pro - AES-256 File/Folder Locker with Modern UI
"""

import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ------------------------------------------------------------
# Constants & Crypto (same robust core)
# ------------------------------------------------------------
MAGIC_HEADER = b'LOCKITv1'
HEADER_LEN = len(MAGIC_HEADER)

def derive_key(password: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=200_000,
        backend=default_backend()
    )
    return kdf.derive(password)

def is_lockit_file(file_path: str) -> bool:
    try:
        with open(file_path, 'rb') as f:
            return f.read(HEADER_LEN) == MAGIC_HEADER
    except:
        return False

def encrypt_file(file_path: str, password: str) -> str:
    if is_lockit_file(file_path):
        raise ValueError("This file is already encrypted. Use 'Unlock' to decrypt it.")

    salt = os.urandom(16)
    key = derive_key(password.encode('utf-8'), salt)
    nonce = os.urandom(12)
    cipher = Cipher(algorithms.AES(key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()

    output_path = file_path + ".lockit"
    with open(file_path, 'rb') as f_in, open(output_path, 'wb') as f_out:
        f_out.write(MAGIC_HEADER)
        f_out.write(salt)
        f_out.write(nonce)
        while True:
            chunk = f_in.read(1024 * 1024)
            if not chunk:
                break
            f_out.write(encryptor.update(chunk))
        encryptor.finalize()
        f_out.write(encryptor.tag)
    os.remove(file_path)
    return output_path

def decrypt_file(encrypted_path: str, password: str) -> str:
    try:
        with open(encrypted_path, 'rb') as f:
            first = f.read(HEADER_LEN)
            f.seek(0)
            if first == MAGIC_HEADER:
                f.read(HEADER_LEN)
                salt = f.read(16)
                nonce = f.read(12)
                f.seek(0, os.SEEK_END)
                size = f.tell()
                tag_start = size - 16
                f.seek(tag_start)
                tag = f.read(16)
                f.seek(HEADER_LEN + 16 + 12)
                ciphertext = f.read(tag_start - (HEADER_LEN + 16 + 12))
            else:
                f.seek(0)
                salt = f.read(16)
                nonce = f.read(12)
                f.seek(0, os.SEEK_END)
                size = f.tell()
                tag_start = size - 16
                f.seek(tag_start)
                tag = f.read(16)
                f.seek(16 + 12)
                ciphertext = f.read(tag_start - (16 + 12))
    except Exception as e:
        raise ValueError(f"Cannot read encrypted file: {str(e)}")

    key = derive_key(password.encode('utf-8'), salt)
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        if encrypted_path.endswith(".lockit"):
            original = encrypted_path[:-7]
        else:
            original = encrypted_path + ".decrypted"
        with open(original, 'wb') as f_out:
            f_out.write(decryptor.update(ciphertext))
            decryptor.finalize()
    except InvalidTag:
        raise ValueError("Incorrect password or corrupted file.")
    except Exception as e:
        raise ValueError(f"Decryption error: {str(e)}")
    os.remove(encrypted_path)
    return original

def lock_folder(folder_path: str, password: str) -> None:
    for root, _, files in os.walk(folder_path):
        for file in files:
            full = os.path.join(root, file)
            if is_lockit_file(full):
                continue
            if os.path.isfile(full):
                encrypt_file(full, password)

def unlock_folder(folder_path: str, password: str) -> None:
    for root, _, files in os.walk(folder_path):
        for file in files:
            full = os.path.join(root, file)
            if full.endswith(".lockit") or is_lockit_file(full):
                decrypt_file(full, password)

# ------------------------------------------------------------
# Modern GUI with ttk styling (no emojis, no Clear button)
# ------------------------------------------------------------
class LockItApp:
    def __init__(self, root):
        self.root = root
        root.title("LockIt Pro - AES-256 File/Folder Locker")
        root.geometry("600x480")
        root.resizable(False, False)
        root.configure(bg='#f5f5f5')
        self.center_window()

        # Style configuration
        self.setup_styles()

        # Main container
        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        title = ttk.Label(main_frame, text="LockIt Pro", font=('Segoe UI', 18, 'bold'))
        title.pack(pady=(0, 15))

        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode", padding="10")
        mode_frame.pack(fill=tk.X, pady=(0, 15))
        self.mode_var = tk.StringVar(value="file")
        ttk.Radiobutton(mode_frame, text="File", variable=self.mode_var, value="file").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(mode_frame, text="Folder", variable=self.mode_var, value="folder").pack(side=tk.LEFT, padx=10)

        # Path selection
        path_frame = ttk.LabelFrame(main_frame, text="Target", padding="10")
        path_frame.pack(fill=tk.X, pady=(0, 15))
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, state='readonly', font=('Segoe UI', 10))
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse, style="Accent.TButton")
        browse_btn.pack(side=tk.RIGHT)

        # Password frame
        pwd_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
        pwd_frame.pack(fill=tk.X, pady=(0, 15))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(pwd_frame, textvariable=self.pass_var, show="*", font=('Segoe UI', 10))
        self.pass_entry.pack(fill=tk.X, pady=(0, 5))
        self.show_pwd = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(pwd_frame, text="Show password", variable=self.show_pwd, command=self.toggle_password)
        chk.pack(anchor=tk.W)

        # Action buttons (Lock / Unlock only)
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 15))
        self.lock_btn = ttk.Button(btn_frame, text="LOCK", command=self.lock, style="Lock.TButton")
        self.lock_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        self.unlock_btn = ttk.Button(btn_frame, text="UNLOCK", command=self.unlock, style="Unlock.TButton")
        self.unlock_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(10, 0))

        # Progress bar
        self.progress = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
        self.progress.pack(fill=tk.X, pady=(0, 10))

        # Status bar (bottom)
        self.status_label = ttk.Label(root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, font=('Segoe UI', 9))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        # Threading
        self.operation_thread = None

    def center_window(self):
        self.root.update_idletasks()
        w = self.root.winfo_width()
        h = self.root.winfo_height()
        x = (self.root.winfo_screenwidth() // 2) - (w // 2)
        y = (self.root.winfo_screenheight() // 2) - (h // 2)
        self.root.geometry(f'{w}x{h}+{x}+{y}')

    def setup_styles(self):
        style = ttk.Style()
        style.theme_use('clam')
        # Colors
        bg = '#f5f5f5'
        fg = '#333333'
        accent = '#0078d7'
        lock_color = '#d9534f'
        unlock_color = '#5bc0de'
        # Configure base styles
        style.configure('.', background=bg, foreground=fg, font=('Segoe UI', 10))
        style.configure('TLabel', background=bg)
        style.configure('TFrame', background=bg)
        style.configure('TLabelframe', background=bg, foreground=fg, font=('Segoe UI', 10, 'bold'))
        style.configure('TLabelframe.Label', background=bg, foreground=fg)
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=6)
        style.map('TButton', background=[('active', '#e6e6e6')])
        # Accent button (Browse)
        style.configure('Accent.TButton', foreground='white', background=accent)
        style.map('Accent.TButton', background=[('active', '#005a9e')])
        # Lock button
        style.configure('Lock.TButton', foreground='white', background=lock_color)
        style.map('Lock.TButton', background=[('active', '#c9302c')])
        # Unlock button
        style.configure('Unlock.TButton', foreground='white', background=unlock_color)
        style.map('Unlock.TButton', background=[('active', '#31b0d5')])
        # Entry
        style.configure('TEntry', fieldbackground='white', padding=4)
        # Progressbar
        style.configure('TProgressbar', background=accent, thickness=8)

    def toggle_password(self):
        self.pass_entry.config(show="" if self.show_pwd.get() else "*")

    def browse(self):
        if self.mode_var.get() == "file":
            path = filedialog.askopenfilename(title="Select a file")
        else:
            path = filedialog.askdirectory(title="Select a folder")
        if path:
            self.path_var.set(path)
            self.status_label.config(text=f"Selected: {os.path.basename(path)}")

    def _run_operation(self, operation_name, func):
        path = self.path_var.get().strip()
        if not path:
            messagebox.showerror("Error", "Please select a file or folder.")
            return
        password = self.pass_var.get()
        if not password:
            messagebox.showerror("Error", "Password cannot be empty.")
            return

        self.lock_btn.config(state=tk.DISABLED)
        self.unlock_btn.config(state=tk.DISABLED)
        self.progress.start(10)
        self.status_label.config(text=f"{operation_name} in progress...")
        self.root.update()

        def target():
            try:
                result = func(path, password)
                self.root.after(0, self._on_success, operation_name, result)
            except ValueError as e:
                self.root.after(0, self._on_error, str(e))
            except Exception as e:
                self.root.after(0, self._on_error, f"Unexpected: {str(e)}")

        self.operation_thread = threading.Thread(target=target, daemon=True)
        self.operation_thread.start()

    def _on_success(self, operation_name, new_path=None):
        self.progress.stop()
        self.lock_btn.config(state=tk.NORMAL)
        self.unlock_btn.config(state=tk.NORMAL)
        if new_path and os.path.exists(new_path):
            self.path_var.set(new_path)
            self.status_label.config(text=f"{operation_name} completed -> {os.path.basename(new_path)}")
        else:
            self.status_label.config(text=f"{operation_name} completed successfully!")
        messagebox.showinfo("Success", f"{operation_name} completed successfully!")
        self.pass_var.set("")
        self.show_pwd.set(False)
        self.toggle_password()

    def _on_error(self, error_msg):
        self.progress.stop()
        self.lock_btn.config(state=tk.NORMAL)
        self.unlock_btn.config(state=tk.NORMAL)
        self.status_label.config(text=f"Error: {error_msg}")
        messagebox.showerror("Error", error_msg)

    def lock(self):
        if self.mode_var.get() == "file":
            self._run_operation("Lock File", lambda p, pw: encrypt_file(p, pw))
        else:
            self._run_operation("Lock Folder", lambda p, pw: lock_folder(p, pw))

    def unlock(self):
        if self.mode_var.get() == "file":
            self._run_operation("Unlock File", lambda p, pw: decrypt_file(p, pw))
        else:
            self._run_operation("Unlock Folder", lambda p, pw: unlock_folder(p, pw))

def main():
    root = tk.Tk()
    app = LockItApp(root)
    root.mainloop()

if __name__ == "__main__":
    main()