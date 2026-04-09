#!/usr/bin/env python3
"""
LockIt Pro v1.1 - AES-256 File/Folder Locker with Unified UI
"""

import sys
import os
import threading
import tkinter as tk
from tkinter import ttk, filedialog, messagebox, simpledialog

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

# ------------------------------------------------------------
# Constants
# ------------------------------------------------------------
MAGIC_HEADER = b'LOCKITv1'
HEADER_LEN = len(MAGIC_HEADER)

# Unified UI Colors and Fonts
UI_BG = '#f5f5f5'
UI_FG = '#333333'
UI_ACCENT = '#0078d7'
UI_LOCK = '#d9534f'
UI_UNLOCK = '#5bc0de'
UI_HOVER_LOCK = '#c9302c'
UI_HOVER_UNLOCK = '#31b0d5'
UI_HOVER_ACCENT = '#005a9e'
UI_FONT_FAMILY = 'Segoe UI'
UI_FONT_SIZE_NORMAL = 10
UI_FONT_SIZE_BOLD = 10
UI_FONT_SIZE_TITLE = 18
UI_FONT_SIZE_SMALL = 9
UI_PADDING = 10
UI_BUTTON_PADDING = 6

# ------------------------------------------------------------
# Crypto Functions
# ------------------------------------------------------------
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

def get_hint_file_path(encrypted_path: str) -> str:
    return encrypted_path + ".hint"

def save_hint(encrypted_path: str, hint: str) -> None:
    with open(get_hint_file_path(encrypted_path), 'w', encoding='utf-8') as f:
        f.write(hint)

def load_hint(encrypted_path: str) -> str:
    try:
        with open(get_hint_file_path(encrypted_path), 'r', encoding='utf-8') as f:
            return f.read()
    except:
        return ""

def shred_file(file_path: str, passes: int = 3) -> None:
    if not os.path.exists(file_path):
        return
    try:
        length = os.path.getsize(file_path)
        chunk_size = 1024 * 1024
        with open(file_path, 'rb+') as f:
            for _ in range(passes):
                f.seek(0)
                remaining = length
                while remaining > 0:
                    write_size = min(chunk_size, remaining)
                    f.write(os.urandom(write_size))
                    remaining -= write_size
                f.flush()
                os.fsync(f.fileno())
            f.seek(0)
            remaining = length
            while remaining > 0:
                write_size = min(chunk_size, remaining)
                f.write(b'\x00' * write_size)
                remaining -= write_size
            f.flush()
            os.fsync(f.fileno())
        os.remove(file_path)
    except Exception as e:
        try:
            os.remove(file_path)
        except:
            pass
        raise ValueError(f"Shredding failed: {str(e)}")

def encrypt_file(file_path: str, password: str, hint: str = "", shred: bool = True) -> str:
    if is_lockit_file(file_path):
        raise ValueError("File is already encrypted.")

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

    if shred:
        shred_file(file_path)
    else:
        os.remove(file_path)

    if hint:
        save_hint(output_path, hint)
    return output_path

def decrypt_file(encrypted_path: str, password: str) -> str:
    if not is_lockit_file(encrypted_path):
        raise ValueError("Not a valid LockIt file.")

    with open(encrypted_path, 'rb') as f:
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

    key = derive_key(password.encode('utf-8'), salt)
    try:
        cipher = Cipher(algorithms.AES(key), modes.GCM(nonce, tag), backend=default_backend())
        decryptor = cipher.decryptor()
        original = encrypted_path[:-7] if encrypted_path.endswith(".lockit") else encrypted_path + ".decrypted"
        with open(original, 'wb') as f_out:
            f_out.write(decryptor.update(ciphertext))
            decryptor.finalize()
    except InvalidTag:
        raise ValueError("Incorrect password or corrupted file.")
    os.remove(encrypted_path)
    hint_path = get_hint_file_path(encrypted_path)
    if os.path.exists(hint_path):
        os.remove(hint_path)
    return original

def lock_folder(folder_path: str, password: str, hint: str = "", shred: bool = True) -> None:
    for root, _, files in os.walk(folder_path):
        for file in files:
            full = os.path.join(root, file)
            if is_lockit_file(full):
                continue
            if os.path.isfile(full):
                encrypt_file(full, password, hint, shred)

def unlock_folder(folder_path: str, password: str) -> None:
    for root, _, files in os.walk(folder_path):
        for file in files:
            full = os.path.join(root, file)
            if full.endswith(".lockit") or is_lockit_file(full):
                decrypt_file(full, password)

# ------------------------------------------------------------
# Unified Style Setup
# ------------------------------------------------------------
def setup_unified_styles():
    style = ttk.Style()
    style.theme_use('clam')
    
    style.configure('.', background=UI_BG, foreground=UI_FG, font=(UI_FONT_FAMILY, UI_FONT_SIZE_NORMAL))
    style.configure('TLabel', background=UI_BG)
    style.configure('TFrame', background=UI_BG)
    style.configure('TLabelframe', background=UI_BG, foreground=UI_FG, font=(UI_FONT_FAMILY, UI_FONT_SIZE_BOLD, 'bold'))
    style.configure('TLabelframe.Label', background=UI_BG, foreground=UI_FG)
    style.configure('TButton', font=(UI_FONT_FAMILY, UI_FONT_SIZE_BOLD, 'bold'), padding=UI_BUTTON_PADDING)
    style.map('TButton', background=[('active', '#e6e6e6')])
    style.configure('Accent.TButton', foreground='white', background=UI_ACCENT)
    style.map('Accent.TButton', background=[('active', UI_HOVER_ACCENT)])
    style.configure('Lock.TButton', foreground='white', background=UI_LOCK)
    style.map('Lock.TButton', background=[('active', UI_HOVER_LOCK)])
    style.configure('Unlock.TButton', foreground='white', background=UI_UNLOCK)
    style.map('Unlock.TButton', background=[('active', UI_HOVER_UNLOCK)])
    style.configure('TEntry', fieldbackground='white', padding=4)
    style.configure('TProgressbar', background=UI_ACCENT, thickness=8)

def center_window(window, width, height):
    window.update_idletasks()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')

def create_title_label(parent, text):
    return ttk.Label(parent, text=text, font=(UI_FONT_FAMILY, UI_FONT_SIZE_TITLE, 'bold'))

def create_status_label(parent):
    return ttk.Label(parent, text="Ready", relief=tk.SUNKEN, anchor=tk.W, font=(UI_FONT_FAMILY, UI_FONT_SIZE_SMALL))

def create_progressbar(parent):
    return ttk.Progressbar(parent, mode='indeterminate', length=400)

# ------------------------------------------------------------
# Password Dialog (Unified UI)
# ------------------------------------------------------------
class PasswordDialog:
    def __init__(self, title, prompt, hint=""):
        self.result = None
        self.dialog = tk.Tk()
        self.dialog.title(title)
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=UI_BG)
        setup_unified_styles()
        center_window(self.dialog, 420, 200)
        
        main = ttk.Frame(self.dialog, padding=UI_PADDING)
        main.pack(fill=tk.BOTH, expand=True)
        
        ttk.Label(main, text=prompt, font=(UI_FONT_FAMILY, UI_FONT_SIZE_NORMAL)).pack(pady=UI_PADDING)
        if hint:
            ttk.Label(main, text=f"Hint: {hint}", foreground='gray').pack()
        
        self.pwd_var = tk.StringVar()
        self.entry = ttk.Entry(main, textvariable=self.pwd_var, show="*", width=35)
        self.entry.pack(pady=UI_PADDING)
        self.entry.focus()
        
        self.show_var = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(main, text="Show password", variable=self.show_var, command=self.toggle_password)
        chk.pack(pady=(0, UI_PADDING))
        
        btn_frame = ttk.Frame(main)
        btn_frame.pack(pady=UI_PADDING)
        ttk.Button(btn_frame, text="OK", command=self.on_ok, style="Accent.TButton", width=12).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="Cancel", command=self.on_cancel, width=12).pack(side=tk.LEFT, padx=5)
        
        self.dialog.bind('<Return>', lambda e: self.on_ok())
        self.dialog.protocol("WM_DELETE_WINDOW", self.on_cancel)
        self.dialog.mainloop()
    
    def toggle_password(self):
        self.entry.config(show="" if self.show_var.get() else "*")
    
    def on_ok(self):
        self.result = self.pwd_var.get()
        self.dialog.destroy()
    
    def on_cancel(self):
        self.dialog.destroy()

# ------------------------------------------------------------
# Properties Dialog (Unified UI)
# ------------------------------------------------------------
class PropertiesDialog:
    def __init__(self, parent, filepath):
        self.filepath = filepath
        self.is_locked = is_lockit_file(filepath)
        self.hint = load_hint(filepath) if self.is_locked else ""

        self.win = tk.Toplevel(parent)
        self.win.title("LockIt File Properties")
        self.win.resizable(False, False)
        self.win.configure(bg=UI_BG)
        setup_unified_styles()
        center_window(self.win, 480, 420)

        main = ttk.Frame(self.win, padding=UI_PADDING)
        main.pack(fill=tk.BOTH, expand=True)

        # File info section
        info_frame = ttk.LabelFrame(main, text="File Information", padding=UI_PADDING)
        info_frame.pack(fill=tk.X, pady=(0, UI_PADDING))
        
        ttk.Label(info_frame, text="Name:", font=(UI_FONT_FAMILY, UI_FONT_SIZE_BOLD, 'bold')).grid(row=0, column=0, sticky='w', pady=3)
        ttk.Label(info_frame, text=os.path.basename(filepath), wraplength=350).grid(row=0, column=1, sticky='w', padx=10)
        
        ttk.Label(info_frame, text="Status:", font=(UI_FONT_FAMILY, UI_FONT_SIZE_BOLD, 'bold')).grid(row=1, column=0, sticky='w', pady=3)
        status = "Locked (Encrypted)" if self.is_locked else "Not Locked"
        ttk.Label(info_frame, text=status).grid(row=1, column=1, sticky='w', padx=10)
        
        ttk.Label(info_frame, text="Path:", font=(UI_FONT_FAMILY, UI_FONT_SIZE_BOLD, 'bold')).grid(row=2, column=0, sticky='w', pady=3)
        ttk.Label(info_frame, text=filepath, wraplength=350).grid(row=2, column=1, sticky='w', padx=10)

        if self.is_locked:
            # Password hint section
            hint_frame = ttk.LabelFrame(main, text="Password Hint", padding=UI_PADDING)
            hint_frame.pack(fill=tk.X, pady=(0, UI_PADDING))
            
            self.hint_var = tk.StringVar(value=self.hint)
            self.hint_entry = ttk.Entry(hint_frame, textvariable=self.hint_var, width=50)
            self.hint_entry.pack(fill=tk.X, pady=(0, 5))
            
            btn_frame = ttk.Frame(hint_frame)
            btn_frame.pack(fill=tk.X)
            ttk.Button(btn_frame, text="Save Hint", command=self.save_hint, style="Accent.TButton", width=15).pack(side=tk.LEFT, padx=(0, 5))
            
            # Password management section
            pwd_frame = ttk.LabelFrame(main, text="Password Management", padding=UI_PADDING)
            pwd_frame.pack(fill=tk.X, pady=(0, UI_PADDING))
            
            ttk.Button(pwd_frame, text="Change Password", command=self.change_password, style="Lock.TButton", width=20).pack()
            ttk.Label(pwd_frame, text="Changing password will re-encrypt the file.", foreground='gray', font=(UI_FONT_FAMILY, UI_FONT_SIZE_SMALL)).pack(pady=(5, 0))
        else:
            ttk.Label(main, text="This file is not encrypted.", foreground='gray', font=(UI_FONT_FAMILY, UI_FONT_SIZE_NORMAL)).pack(pady=20)

        # Close button
        ttk.Button(main, text="Close", command=self.win.destroy, style="Accent.TButton", width=15).pack(pady=UI_PADDING)

    def save_hint(self):
        new_hint = self.hint_var.get().strip()
        save_hint(self.filepath, new_hint)
        messagebox.showinfo("Success", "Password hint saved successfully.")

    def change_password(self):
        import shutil
        current_pw = simpledialog.askstring("Change Password", "Enter current password:", show='*', parent=self.win)
        if not current_pw:
            return
        temp_lock = self.filepath + ".temp"
        shutil.copy2(self.filepath, temp_lock)
        try:
            decrypted_path = decrypt_file(temp_lock, current_pw)
            new_pw = simpledialog.askstring("Change Password", "Enter new password:", show='*', parent=self.win)
            if not new_pw:
                os.remove(decrypted_path)
                return
            new_hint = simpledialog.askstring("Change Password", "Enter new hint (optional):", parent=self.win)
            encrypt_file(decrypted_path, new_pw, new_hint or "", shred=False)
            messagebox.showinfo("Success", "Password changed successfully.")
            self.hint_var.set(new_hint or "")
        except Exception as e:
            messagebox.showerror("Error", str(e))
            os.remove(temp_lock)

# ------------------------------------------------------------
# Main GUI Application
# ------------------------------------------------------------
class LockItApp:
    def __init__(self, root):
        self.root = root
        root.title("LockIt Pro - AES-256 File/Folder Locker")
        root.resizable(False, False)
        root.configure(bg=UI_BG)
        setup_unified_styles()
        center_window(root, 640, 540)
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

        main_frame = ttk.Frame(root, padding=UI_PADDING)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # Title
        create_title_label(main_frame, "LockIt Pro").pack(pady=(0, UI_PADDING))

        # Mode selection
        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode", padding=UI_PADDING)
        mode_frame.pack(fill=tk.X, pady=(0, UI_PADDING))
        self.mode_var = tk.StringVar(value="file")
        ttk.Radiobutton(mode_frame, text="File", variable=self.mode_var, value="file").pack(side=tk.LEFT, padx=UI_PADDING)
        ttk.Radiobutton(mode_frame, text="Folder", variable=self.mode_var, value="folder").pack(side=tk.LEFT, padx=UI_PADDING)

        # Target selection
        target_frame = ttk.LabelFrame(main_frame, text="Target", padding=UI_PADDING)
        target_frame.pack(fill=tk.X, pady=(0, UI_PADDING))
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(target_frame, textvariable=self.path_var, state='readonly')
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, UI_PADDING))
        ttk.Button(target_frame, text="Browse", command=self.browse, style="Accent.TButton", width=12).pack(side=tk.RIGHT)

        # Password section
        pwd_frame = ttk.LabelFrame(main_frame, text="Password", padding=UI_PADDING)
        pwd_frame.pack(fill=tk.X, pady=(0, UI_PADDING))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(pwd_frame, textvariable=self.pass_var, show="*")
        self.pass_entry.pack(fill=tk.X, pady=(0, 5))
        self.show_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(pwd_frame, text="Show password", variable=self.show_pwd, command=self.toggle_password).pack(anchor=tk.W)

        # Shred option
        self.shred_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main_frame, text="Securely shred original files (overwrite before delete)", 
                        variable=self.shred_var).pack(anchor=tk.W, pady=(0, UI_PADDING))

        # Action buttons
        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, UI_PADDING))
        self.lock_btn = ttk.Button(btn_frame, text="LOCK", command=self.lock, style="Lock.TButton")
        self.lock_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        self.unlock_btn = ttk.Button(btn_frame, text="UNLOCK", command=self.unlock, style="Unlock.TButton")
        self.unlock_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))

        # Progress bar
        self.progress = create_progressbar(main_frame)
        self.progress.pack(fill=tk.X, pady=(0, UI_PADDING))

        # Status bar
        self.status_label = create_status_label(root)
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

        self.operation_thread = None

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
            except Exception as e:
                self.root.after(0, self._on_error, str(e))

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
        shred = self.shred_var.get()
        if self.mode_var.get() == "file":
            self._run_operation("Lock File", lambda p, pw: encrypt_file(p, pw, shred=shred))
        else:
            self._run_operation("Lock Folder", lambda p, pw: lock_folder(p, pw, shred=shred))

    def unlock(self):
        if self.mode_var.get() == "file":
            self._run_operation("Unlock File", lambda p, pw: decrypt_file(p, pw))
        else:
            self._run_operation("Unlock Folder", lambda p, pw: unlock_folder(p, pw))

    def on_closing(self):
        self.root.destroy()
        sys.exit(0)

# ------------------------------------------------------------
# Context Menu Handlers
# ------------------------------------------------------------
def handle_context_menu():
    if len(sys.argv) < 2:
        return
    action = sys.argv[1].lower()
    if action == "--lock" and len(sys.argv) >= 3:
        target = sys.argv[2]
        shred = True
        if os.path.isdir(target):
            pwd_dialog = PasswordDialog("Lock Folder", "Enter password to lock this folder:")
            if pwd_dialog.result:
                hint = simpledialog.askstring("Password Hint", "Enter a hint for this password (optional):")
                try:
                    lock_folder(target, pwd_dialog.result, hint or "", shred)
                    messagebox.showinfo("Success", f"Folder locked: {target}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        else:
            if is_lockit_file(target):
                messagebox.showerror("Error", "File is already locked. Use Unlock.")
                sys.exit(0)
            pwd_dialog = PasswordDialog("Lock File", f"Enter password to lock:\n{os.path.basename(target)}")
            if pwd_dialog.result:
                hint = simpledialog.askstring("Password Hint", "Enter a hint for this password (optional):")
                try:
                    new_path = encrypt_file(target, pwd_dialog.result, hint or "", shred)
                    messagebox.showinfo("Success", f"File locked: {new_path}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        sys.exit(0)
    elif action == "--unlock" and len(sys.argv) >= 3:
        target = sys.argv[2]
        if os.path.isdir(target):
            pwd_dialog = PasswordDialog("Unlock Folder", "Enter password to unlock this folder:")
            if pwd_dialog.result:
                try:
                    unlock_folder(target, pwd_dialog.result)
                    messagebox.showinfo("Success", f"Folder unlocked: {target}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        else:
            if not is_lockit_file(target):
                messagebox.showerror("Error", "File is not locked or not a valid LockIt file.")
                sys.exit(0)
            hint = load_hint(target)
            pwd_dialog = PasswordDialog("Unlock File", f"Enter password to unlock:\n{os.path.basename(target)}", hint)
            if pwd_dialog.result:
                try:
                    original = decrypt_file(target, pwd_dialog.result)
                    messagebox.showinfo("Success", f"File unlocked: {original}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        sys.exit(0)
    elif action == "--properties" and len(sys.argv) >= 3:
        target = sys.argv[2]
        root = tk.Tk()
        root.withdraw()
        setup_unified_styles()
        PropertiesDialog(root, target)
        root.mainloop()
        sys.exit(0)
    else:
        main_gui()

def main_gui():
    root = tk.Tk()
    app = LockItApp(root)
    root.mainloop()
    sys.exit(0)

if __name__ == "__main__":
    if len(sys.argv) > 1:
        handle_context_menu()
    else:
        main_gui()