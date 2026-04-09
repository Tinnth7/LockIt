#!/usr/bin/env python3
"""
LockIt Pro v1.1 - AES-256 File/Folder Locker with Fully Synchronized UI
"""

import sys
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
# Global UI Constants
# ------------------------------------------------------------
UI = {
    'bg': '#f5f5f5',
    'fg': '#333333',
    'accent': '#0078d7',
    'lock': '#d9534f',
    'unlock': '#5bc0de',
    'font_family': 'Segoe UI',
    'font_size_title': 18,
    'font_size_bold': 10,
    'font_size_normal': 10,
    'font_size_small': 9,
    'padding': 10,
    'button_padding': 6,
    'window_width': 620,
    'window_height': 540,
    'dialog_width': 420,
    'dialog_height': 200,
    'hint_width': 400,
    'hint_height': 180,
    'prop_width': 500,
    'prop_height': 450,
}

# ------------------------------------------------------------
# Crypto Functions
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
# Unified UI Helper Functions
# ------------------------------------------------------------
def setup_styles():
    style = ttk.Style()
    style.theme_use('clam')
    style.configure('.', background=UI['bg'], foreground=UI['fg'], 
                   font=(UI['font_family'], UI['font_size_normal']))
    style.configure('TLabel', background=UI['bg'])
    style.configure('TFrame', background=UI['bg'])
    style.configure('TLabelframe', background=UI['bg'], foreground=UI['fg'],
                   font=(UI['font_family'], UI['font_size_bold'], 'bold'))
    style.configure('TLabelframe.Label', background=UI['bg'], foreground=UI['fg'])
    style.configure('TButton', font=(UI['font_family'], UI['font_size_bold'], 'bold'),
                   padding=UI['button_padding'])
    style.map('TButton', background=[('active', '#e6e6e6')])
    style.configure('Accent.TButton', foreground='white', background=UI['accent'])
    style.map('Accent.TButton', background=[('active', '#005a9e')])
    style.configure('Lock.TButton', foreground='white', background=UI['lock'])
    style.map('Lock.TButton', background=[('active', '#c9302c')])
    style.configure('Unlock.TButton', foreground='white', background=UI['unlock'])
    style.map('Unlock.TButton', background=[('active', '#31b0d5')])
    style.configure('TEntry', fieldbackground='white', padding=4)
    style.configure('TProgressbar', background=UI['accent'], thickness=8)

def center_window(window, width, height):
    window.update_idletasks()
    x = (window.winfo_screenwidth() // 2) - (width // 2)
    y = (window.winfo_screenheight() // 2) - (height // 2)
    window.geometry(f'{width}x{height}+{x}+{y}')

def create_title(parent, text):
    return ttk.Label(parent, text=text, 
                     font=(UI['font_family'], UI['font_size_title'], 'bold'))

def create_status_bar(parent):
    return ttk.Label(parent, text="Ready", relief=tk.SUNKEN, anchor=tk.W,
                     font=(UI['font_family'], UI['font_size_small']))

# ------------------------------------------------------------
# Password Dialog (Fixed)
# ------------------------------------------------------------
class PasswordDialog:
    def __init__(self, title, prompt, hint=""):
        self.result = None
        self.dialog = tk.Tk()
        self.dialog.title(title)
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=UI['bg'])
        
        w, h = UI['dialog_width'], UI['dialog_height']
        x = (self.dialog.winfo_screenwidth() // 2) - (w // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (h // 2)
        self.dialog.geometry(f'{w}x{h}+{x}+{y}')
        
        main = tk.Frame(self.dialog, bg=UI['bg'])
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(main, text=prompt, bg=UI['bg'], fg=UI['fg'],
                font=(UI['font_family'], UI['font_size_normal']),
                wraplength=350, justify='center').pack(pady=(0, 10))
        
        if hint:
            tk.Label(main, text=f"Hint: {hint}", bg=UI['bg'], fg='gray',
                    font=(UI['font_family'], UI['font_size_small'])).pack(pady=(0, 10))
        
        self.pwd_var = tk.StringVar()
        self.entry = tk.Entry(main, textvariable=self.pwd_var, show="*",
                             font=(UI['font_family'], UI['font_size_normal']),
                             bg='white', width=35)
        self.entry.pack(pady=(0, 10))
        self.entry.focus()
        
        self.show_var = tk.BooleanVar(value=False)
        tk.Checkbutton(main, text="Show password", variable=self.show_var,
                      bg=UI['bg'], command=self.toggle_password).pack(pady=(0, 15))
        
        btn_frame = tk.Frame(main, bg=UI['bg'])
        btn_frame.pack()
        
        tk.Button(btn_frame, text="OK", command=self.ok,
                 bg=UI['accent'], fg='white',
                 font=(UI['font_family'], UI['font_size_bold'], 'bold'),
                 padx=25, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Cancel", command=self.cancel,
                 bg='#e0e0e0', fg=UI['fg'],
                 font=(UI['font_family'], UI['font_size_bold'], 'bold'),
                 padx=25, pady=5).pack(side=tk.LEFT, padx=5)
        
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.protocol("WM_DELETE_WINDOW", self.cancel)
        self.dialog.mainloop()
    
    def toggle_password(self):
        self.entry.config(show="" if self.show_var.get() else "*")
    
    def ok(self):
        self.result = self.pwd_var.get()
        self.dialog.destroy()
    
    def cancel(self):
        self.dialog.destroy()

# ------------------------------------------------------------
# Hint Dialog (Fixed)
# ------------------------------------------------------------
class HintDialog:
    def __init__(self, title, prompt):
        self.result = None
        self.dialog = tk.Tk()
        self.dialog.title(title)
        self.dialog.resizable(False, False)
        self.dialog.configure(bg=UI['bg'])
        
        w, h = UI['hint_width'], UI['hint_height']
        x = (self.dialog.winfo_screenwidth() // 2) - (w // 2)
        y = (self.dialog.winfo_screenheight() // 2) - (h // 2)
        self.dialog.geometry(f'{w}x{h}+{x}+{y}')
        
        main = tk.Frame(self.dialog, bg=UI['bg'])
        main.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        tk.Label(main, text=prompt, bg=UI['bg'], fg=UI['fg'],
                font=(UI['font_family'], UI['font_size_normal'])).pack(pady=(0, 10))
        
        self.hint_var = tk.StringVar()
        self.entry = tk.Entry(main, textvariable=self.hint_var,
                             font=(UI['font_family'], UI['font_size_normal']),
                             bg='white', width=40)
        self.entry.pack(pady=(0, 15))
        self.entry.focus()
        
        btn_frame = tk.Frame(main, bg=UI['bg'])
        btn_frame.pack()
        
        tk.Button(btn_frame, text="OK", command=self.ok,
                 bg=UI['accent'], fg='white',
                 font=(UI['font_family'], UI['font_size_bold'], 'bold'),
                 padx=25, pady=5).pack(side=tk.LEFT, padx=5)
        
        tk.Button(btn_frame, text="Skip", command=self.skip,
                 bg='#e0e0e0', fg=UI['fg'],
                 font=(UI['font_family'], UI['font_size_bold'], 'bold'),
                 padx=25, pady=5).pack(side=tk.LEFT, padx=5)
        
        self.dialog.bind('<Return>', lambda e: self.ok())
        self.dialog.protocol("WM_DELETE_WINDOW", self.skip)
        self.dialog.mainloop()
    
    def ok(self):
        self.result = self.hint_var.get()
        self.dialog.destroy()
    
    def skip(self):
        self.result = ""
        self.dialog.destroy()

# ------------------------------------------------------------
# Properties Dialog (Synchronized)
# ------------------------------------------------------------
class PropertiesDialog:
    def __init__(self, parent, filepath):
        self.filepath = filepath
        self.is_locked = is_lockit_file(filepath)
        self.hint = load_hint(filepath) if self.is_locked else ""

        self.win = tk.Toplevel(parent)
        self.win.title("LockIt File Properties")
        self.win.resizable(False, False)
        self.win.configure(bg=UI['bg'])
        setup_styles()
        center_window(self.win, UI['prop_width'], UI['prop_height'])

        main = ttk.Frame(self.win, padding=UI['padding'])
        main.pack(fill=tk.BOTH, expand=True)

        # Info section
        info = ttk.LabelFrame(main, text="File Information", padding=UI['padding'])
        info.pack(fill=tk.X, pady=(0, UI['padding']))
        
        row = 0
        for label, value in [
            ("Name:", os.path.basename(filepath)),
            ("Status:", "Locked (Encrypted)" if self.is_locked else "Not Locked"),
            ("Path:", filepath)
        ]:
            ttk.Label(info, text=label, font=(UI['font_family'], UI['font_size_bold'], 'bold')).grid(row=row, column=0, sticky='w', pady=3)
            ttk.Label(info, text=value, wraplength=350).grid(row=row, column=1, sticky='w', padx=10)
            row += 1

        if self.is_locked:
            # Hint section
            hint_frame = ttk.LabelFrame(main, text="Password Hint", padding=UI['padding'])
            hint_frame.pack(fill=tk.X, pady=(0, UI['padding']))
            
            self.hint_var = tk.StringVar(value=self.hint)
            self.hint_entry = ttk.Entry(hint_frame, textvariable=self.hint_var)
            self.hint_entry.pack(fill=tk.X, pady=(0, 5))
            
            ttk.Button(hint_frame, text="Save Hint", command=self.save_hint,
                      style="Accent.TButton").pack()
            
            # Password management
            pwd_frame = ttk.LabelFrame(main, text="Password Management", padding=UI['padding'])
            pwd_frame.pack(fill=tk.X, pady=(0, UI['padding']))
            
            ttk.Button(pwd_frame, text="Change Password", command=self.change_password,
                      style="Lock.TButton").pack()
            ttk.Label(pwd_frame, text="Changing password will re-encrypt the file.",
                     foreground='gray', font=(UI['font_family'], UI['font_size_small'])).pack(pady=(5, 0))
        else:
            ttk.Label(main, text="This file is not encrypted.", foreground='gray').pack(pady=20)

        ttk.Button(main, text="Close", command=self.win.destroy,
                  style="Accent.TButton", width=15).pack(pady=UI['padding'])

    def save_hint(self):
        save_hint(self.filepath, self.hint_var.get().strip())
        messagebox.showinfo("Success", "Password hint saved.")

    def change_password(self):
        import shutil
        pw_dialog = PasswordDialog("Change Password", "Enter current password:")
        if not pw_dialog.result:
            return
        temp = self.filepath + ".temp"
        shutil.copy2(self.filepath, temp)
        try:
            decrypted = decrypt_file(temp, pw_dialog.result)
            new_pw_dialog = PasswordDialog("Change Password", "Enter new password:")
            if not new_pw_dialog.result:
                os.remove(decrypted)
                return
            new_hint_dialog = HintDialog("Password Hint", "Enter new hint (optional):")
            encrypt_file(decrypted, new_pw_dialog.result, new_hint_dialog.result, shred=False) # type: ignore
            messagebox.showinfo("Success", "Password changed successfully.")
            self.hint_var.set(new_hint_dialog.result) # pyright: ignore[reportArgumentType]
        except Exception as e:
            messagebox.showerror("Error", str(e))
            os.remove(temp)

# ------------------------------------------------------------
# Main Application
# ------------------------------------------------------------
class LockItApp:
    def __init__(self, root):
        self.root = root
        root.title("LockIt Pro - AES-256 File/Folder Locker")
        root.resizable(False, False)
        root.configure(bg=UI['bg'])
        setup_styles()
        center_window(root, UI['window_width'], UI['window_height'])
        root.protocol("WM_DELETE_WINDOW", self.on_closing)

        main = ttk.Frame(root, padding=UI['padding'])
        main.pack(fill=tk.BOTH, expand=True)

        # Title
        create_title(main, "LockIt Pro").pack(pady=(0, UI['padding']))

        # Mode
        mode_frame = ttk.LabelFrame(main, text="Operation Mode", padding=UI['padding'])
        mode_frame.pack(fill=tk.X, pady=(0, UI['padding']))
        self.mode_var = tk.StringVar(value="file")
        ttk.Radiobutton(mode_frame, text="File", variable=self.mode_var, value="file").pack(side=tk.LEFT, padx=UI['padding'])
        ttk.Radiobutton(mode_frame, text="Folder", variable=self.mode_var, value="folder").pack(side=tk.LEFT, padx=UI['padding'])

        # Target
        target_frame = ttk.LabelFrame(main, text="Target", padding=UI['padding'])
        target_frame.pack(fill=tk.X, pady=(0, UI['padding']))
        self.path_var = tk.StringVar()
        self.path_entry = ttk.Entry(target_frame, textvariable=self.path_var, state='readonly')
        self.path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, UI['padding']))
        ttk.Button(target_frame, text="Browse", command=self.browse, style="Accent.TButton", width=12).pack(side=tk.RIGHT)

        # Password
        pwd_frame = ttk.LabelFrame(main, text="Password", padding=UI['padding'])
        pwd_frame.pack(fill=tk.X, pady=(0, UI['padding']))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(pwd_frame, textvariable=self.pass_var, show="*")
        self.pass_entry.pack(fill=tk.X, pady=(0, 5))
        self.show_pwd = tk.BooleanVar(value=False)
        ttk.Checkbutton(pwd_frame, text="Show password", variable=self.show_pwd,
                       command=self.toggle_password).pack(anchor=tk.W)

        # Shred
        self.shred_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(main, text="Securely shred original files (overwrite before delete)",
                       variable=self.shred_var).pack(anchor=tk.W, pady=(0, UI['padding']))

        # Buttons
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=(0, UI['padding']))
        self.lock_btn = ttk.Button(btn_frame, text="LOCK", command=self.lock, style="Lock.TButton")
        self.lock_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 5))
        self.unlock_btn = ttk.Button(btn_frame, text="UNLOCK", command=self.unlock, style="Unlock.TButton")
        self.unlock_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(5, 0))

        # Progress
        self.progress = ttk.Progressbar(main, mode='indeterminate')
        self.progress.pack(fill=tk.X, pady=(0, UI['padding']))

        # Status
        self.status_label = create_status_bar(root)
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
            self.status_label.config(text=f"{operation_name} completed!")
        messagebox.showinfo("Success", f"{operation_name} completed!")
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
        if os.path.isdir(target):
            pwd_dlg = PasswordDialog("Lock Folder", "Enter password to lock this folder:")
            if pwd_dlg.result:
                hint_dlg = HintDialog("Password Hint", "Enter a hint for this password (optional):")
                try:
                    lock_folder(target, pwd_dlg.result, hint_dlg.result, True) # type: ignore
                    messagebox.showinfo("Success", f"Folder locked: {target}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        else:
            if is_lockit_file(target):
                messagebox.showerror("Error", "File is already locked. Use Unlock.")
                sys.exit(0)
            pwd_dlg = PasswordDialog("Lock File", f"Enter password to lock:\n{os.path.basename(target)}")
            if pwd_dlg.result:
                hint_dlg = HintDialog("Password Hint", "Enter a hint for this password (optional):")
                try:
                    new_path = encrypt_file(target, pwd_dlg.result, hint_dlg.result, True) # type: ignore
                    messagebox.showinfo("Success", f"File locked: {new_path}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        sys.exit(0)
        
    elif action == "--unlock" and len(sys.argv) >= 3:
        target = sys.argv[2]
        if os.path.isdir(target):
            pwd_dlg = PasswordDialog("Unlock Folder", "Enter password to unlock this folder:")
            if pwd_dlg.result:
                try:
                    unlock_folder(target, pwd_dlg.result)
                    messagebox.showinfo("Success", f"Folder unlocked: {target}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        else:
            if not is_lockit_file(target):
                messagebox.showerror("Error", "File is not locked or not a valid LockIt file.")
                sys.exit(0)
            hint = load_hint(target)
            pwd_dlg = PasswordDialog("Unlock File", f"Enter password to unlock:\n{os.path.basename(target)}", hint)
            if pwd_dlg.result:
                try:
                    original = decrypt_file(target, pwd_dlg.result)
                    messagebox.showinfo("Success", f"File unlocked: {original}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        sys.exit(0)
        
    elif action == "--properties" and len(sys.argv) >= 3:
        target = sys.argv[2]
        root = tk.Tk()
        root.withdraw()
        setup_styles()
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