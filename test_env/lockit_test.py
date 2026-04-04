#!/usr/bin/env python3
"""
LockIt Pro - AES-256 File/Folder Locker with Context Menu Support
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
# Constants & Crypto
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
    """Securely overwrite a file then delete."""
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
            # zero pass
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
# Properties Dialog
# ------------------------------------------------------------
class PropertiesDialog:
    def __init__(self, parent, filepath):
        self.filepath = filepath
        self.is_locked = is_lockit_file(filepath)
        self.hint = load_hint(filepath) if self.is_locked else ""

        self.win = tk.Toplevel(parent)
        self.win.title("LockIt File Properties")
        self.win.geometry("450x350")
        self.win.resizable(False, False)
        self.win.configure(bg='#f5f5f5')
        self.center_window()

        main = ttk.Frame(self.win, padding="15")
        main.pack(fill=tk.BOTH, expand=True)

        ttk.Label(main, text="File:", font=('Segoe UI', 10, 'bold')).grid(row=0, column=0, sticky='w', pady=5)
        ttk.Label(main, text=os.path.basename(filepath), wraplength=300).grid(row=0, column=1, sticky='w', padx=10)

        ttk.Label(main, text="Status:", font=('Segoe UI', 10, 'bold')).grid(row=1, column=0, sticky='w', pady=5)
        status = "Locked (encrypted)" if self.is_locked else "Not locked"
        ttk.Label(main, text=status).grid(row=1, column=1, sticky='w', padx=10)

        ttk.Label(main, text="Full Path:", font=('Segoe UI', 10, 'bold')).grid(row=2, column=0, sticky='w', pady=5)
        ttk.Label(main, text=filepath, wraplength=300).grid(row=2, column=1, sticky='w', padx=10)

        if self.is_locked:
            ttk.Separator(main, orient='horizontal').grid(row=3, column=0, columnspan=2, sticky='ew', pady=10)
            ttk.Label(main, text="Password Hint:", font=('Segoe UI', 10, 'bold')).grid(row=4, column=0, sticky='w', pady=5)
            self.hint_var = tk.StringVar(value=self.hint)
            self.hint_entry = ttk.Entry(main, textvariable=self.hint_var, width=40)
            self.hint_entry.grid(row=4, column=1, sticky='w', padx=10)
            ttk.Button(main, text="Save Hint", command=self.save_hint, style="Accent.TButton").grid(row=5, column=1, sticky='e', pady=10)
            ttk.Button(main, text="Change Password", command=self.change_password, style="Lock.TButton").grid(row=6, column=1, sticky='e', pady=5)
        else:
            ttk.Label(main, text="This file is not encrypted. Use 'Lock' to protect it.", foreground='gray').grid(row=4, column=0, columnspan=2, pady=20)

        ttk.Button(main, text="Close", command=self.win.destroy).grid(row=7, column=1, sticky='e', pady=10)

    def center_window(self):
        self.win.update_idletasks()
        w = self.win.winfo_width()
        h = self.win.winfo_height()
        x = (self.win.winfo_screenwidth() // 2) - (w // 2)
        y = (self.win.winfo_screenheight() // 2) - (h // 2)
        self.win.geometry(f'{w}x{h}+{x}+{y}')

    def save_hint(self):
        new_hint = self.hint_var.get().strip()
        save_hint(self.filepath, new_hint)
        messagebox.showinfo("Success", "Password hint saved.")

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
        except Exception as e:
            messagebox.showerror("Error", str(e))
            os.remove(temp_lock)

# ------------------------------------------------------------
# GUI Application (Main Window)
# ------------------------------------------------------------
class LockItApp:
    def __init__(self, root):
        self.root = root
        root.title("LockIt Pro - AES-256 File/Folder Locker")
        root.geometry("620x520")
        root.resizable(False, False)
        root.configure(bg='#f5f5f5')
        self.center_window()
        self.setup_styles()

        main_frame = ttk.Frame(root, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)

        title = ttk.Label(main_frame, text="LockIt Pro", font=('Segoe UI', 18, 'bold'))
        title.pack(pady=(0, 15))

        mode_frame = ttk.LabelFrame(main_frame, text="Operation Mode", padding="10")
        mode_frame.pack(fill=tk.X, pady=(0, 15))
        self.mode_var = tk.StringVar(value="file")
        ttk.Radiobutton(mode_frame, text="File", variable=self.mode_var, value="file").pack(side=tk.LEFT, padx=10)
        ttk.Radiobutton(mode_frame, text="Folder", variable=self.mode_var, value="folder").pack(side=tk.LEFT, padx=10)

        path_frame = ttk.LabelFrame(main_frame, text="Target", padding="10")
        path_frame.pack(fill=tk.X, pady=(0, 15))
        self.path_var = tk.StringVar()
        path_entry = ttk.Entry(path_frame, textvariable=self.path_var, state='readonly', font=('Segoe UI', 10))
        path_entry.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        browse_btn = ttk.Button(path_frame, text="Browse", command=self.browse, style="Accent.TButton")
        browse_btn.pack(side=tk.RIGHT)

        pwd_frame = ttk.LabelFrame(main_frame, text="Password", padding="10")
        pwd_frame.pack(fill=tk.X, pady=(0, 15))
        self.pass_var = tk.StringVar()
        self.pass_entry = ttk.Entry(pwd_frame, textvariable=self.pass_var, show="*", font=('Segoe UI', 10))
        self.pass_entry.pack(fill=tk.X, pady=(0, 5))
        self.show_pwd = tk.BooleanVar(value=False)
        chk = ttk.Checkbutton(pwd_frame, text="Show password", variable=self.show_pwd, command=self.toggle_password)
        chk.pack(anchor=tk.W)

        self.shred_var = tk.BooleanVar(value=True)
        shred_frame = ttk.Frame(main_frame)
        shred_frame.pack(fill=tk.X, pady=(0, 10))
        ttk.Checkbutton(shred_frame, text="Securely shred original files (overwrite before delete)", 
                        variable=self.shred_var).pack(anchor=tk.W)

        btn_frame = ttk.Frame(main_frame)
        btn_frame.pack(fill=tk.X, pady=(0, 15))
        self.lock_btn = ttk.Button(btn_frame, text="LOCK", command=self.lock, style="Lock.TButton")
        self.lock_btn.pack(side=tk.LEFT, expand=True, fill=tk.X, padx=(0, 10))
        self.unlock_btn = ttk.Button(btn_frame, text="UNLOCK", command=self.unlock, style="Unlock.TButton")
        self.unlock_btn.pack(side=tk.RIGHT, expand=True, fill=tk.X, padx=(10, 0))

        self.progress = ttk.Progressbar(main_frame, mode='indeterminate', length=400)
        self.progress.pack(fill=tk.X, pady=(0, 10))

        self.status_label = ttk.Label(root, text="Ready", relief=tk.SUNKEN, anchor=tk.W, font=('Segoe UI', 9))
        self.status_label.pack(side=tk.BOTTOM, fill=tk.X)

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
        bg = '#f5f5f5'
        fg = '#333333'
        accent = '#0078d7'
        lock_color = '#d9534f'
        unlock_color = '#5bc0de'
        style.configure('.', background=bg, foreground=fg, font=('Segoe UI', 10))
        style.configure('TLabel', background=bg)
        style.configure('TFrame', background=bg)
        style.configure('TLabelframe', background=bg, foreground=fg, font=('Segoe UI', 10, 'bold'))
        style.configure('TLabelframe.Label', background=bg, foreground=fg)
        style.configure('TButton', font=('Segoe UI', 10, 'bold'), padding=6)
        style.map('TButton', background=[('active', '#e6e6e6')])
        style.configure('Accent.TButton', foreground='white', background=accent)
        style.map('Accent.TButton', background=[('active', '#005a9e')])
        style.configure('Lock.TButton', foreground='white', background=lock_color)
        style.map('Lock.TButton', background=[('active', '#c9302c')])
        style.configure('Unlock.TButton', foreground='white', background=unlock_color)
        style.map('Unlock.TButton', background=[('active', '#31b0d5')])
        style.configure('TEntry', fieldbackground='white', padding=4)
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

# ------------------------------------------------------------
# Command-line handlers for context menu
# ------------------------------------------------------------
def show_password_dialog(title, prompt, hint=""):
    """Simple password popup for command-line operations."""
    dialog = tk.Tk()
    dialog.title(title)
    dialog.geometry("400x180")
    dialog.resizable(False, False)
    dialog.configure(bg='#f5f5f5')
    dialog.update_idletasks()
    x = (dialog.winfo_screenwidth() // 2) - 200
    y = (dialog.winfo_screenheight() // 2) - 90
    dialog.geometry(f'+{x}+{y}')

    result = [None]
    ttk.Label(dialog, text=prompt, font=('Segoe UI', 10)).pack(pady=10)
    if hint:
        ttk.Label(dialog, text=f"Hint: {hint}", foreground='gray').pack()
    pwd_var = tk.StringVar()
    entry = ttk.Entry(dialog, textvariable=pwd_var, show="*", width=30)
    entry.pack(pady=10)
    entry.focus()

    def on_ok():
        result[0] = pwd_var.get() # type: ignore
        dialog.destroy()
    def on_cancel():
        dialog.destroy()
    btn_frame = ttk.Frame(dialog)
    btn_frame.pack(pady=10)
    ttk.Button(btn_frame, text="OK", command=on_ok, style="Accent.TButton").pack(side=tk.LEFT, padx=5)
    ttk.Button(btn_frame, text="Cancel", command=on_cancel).pack(side=tk.LEFT, padx=5)
    dialog.bind('<Return>', lambda e: on_ok())
    dialog.mainloop()
    return result[0]

def handle_context_menu():
    if len(sys.argv) < 2:
        return
    action = sys.argv[1].lower()
    if action == "--lock" and len(sys.argv) >= 3:
        target = sys.argv[2]
        shred = True   # default shred for context menu
        if os.path.isdir(target):
            password = show_password_dialog("Lock Folder", "Enter password to lock this folder:")
            if password:
                hint = simpledialog.askstring("Password Hint", "Enter a hint for this password (optional):")
                try:
                    lock_folder(target, password, hint or "", shred)
                    messagebox.showinfo("Success", f"Folder locked: {target}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        else:
            if is_lockit_file(target):
                messagebox.showerror("Error", "File is already locked. Use Unlock.")
                return
            password = show_password_dialog("Lock File", f"Enter password to lock:\n{os.path.basename(target)}")
            if password:
                hint = simpledialog.askstring("Password Hint", "Enter a hint for this password (optional):")
                try:
                    new_path = encrypt_file(target, password, hint or "", shred)
                    messagebox.showinfo("Success", f"File locked: {new_path}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
    elif action == "--unlock" and len(sys.argv) >= 3:
        target = sys.argv[2]
        if os.path.isdir(target):
            password = show_password_dialog("Unlock Folder", "Enter password to unlock this folder:")
            if password:
                try:
                    unlock_folder(target, password)
                    messagebox.showinfo("Success", f"Folder unlocked: {target}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
        else:
            if not is_lockit_file(target):
                messagebox.showerror("Error", "File is not locked or not a valid LockIt file.")
                return
            hint = load_hint(target)
            prompt = f"Enter password to unlock:\n{os.path.basename(target)}"
            password = show_password_dialog("Unlock File", prompt, hint)
            if password:
                try:
                    original = decrypt_file(target, password)
                    messagebox.showinfo("Success", f"File unlocked: {original}")
                except Exception as e:
                    messagebox.showerror("Error", str(e))
    elif action == "--properties" and len(sys.argv) >= 3:
        target = sys.argv[2]
        root = tk.Tk()
        root.withdraw()
        PropertiesDialog(root, target)
        root.mainloop()
    else:
        main_gui()

def main_gui():
    root = tk.Tk()
    app = LockItApp(root)
    root.mainloop()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        handle_context_menu()
    else:
        main_gui()