# ✨ LockIt Pro ✨

**A simple, lightweight file & folder encryption tool for Windows.**  
Built with Python | AES-256-GCM encryption | No cloud. No tracking. Just locks.

---

##  Features

-  **AES-256-GCM encryption** — military-grade protection for your files and folders
-  **File & Folder support** — lock individual files or entire folders at once
-  **Secure shredding** — original files are overwritten 3 times before deletion
-  **Password confirmation** — prevents accidental lockouts from typos
-  **Right-click menu** — lock/unlock directly from Windows Explorer

---

## 📥 Download

Head to the [Releases](https://github.com/Tinnth7/LockIt/releases) page to download the latest version.

---

## 🚀 How to Use

### Locking a file
1. Open LockIt Pro
2. Select **File** mode
3. Browse and select your file
4. Enter and confirm your password
5. Click **LOCK** 

### Unlocking a file
1. Open LockIt Pro
2. Select **File** mode
3. Browse and select the `.lockit` file
4. Enter your password
5. Click **UNLOCK** 

### Right-click menu
Right-click any file or folder in Windows Explorer and select **Lock with LockIt** or **Unlock with LockIt**.

---

##  Important

- **Do not forget your password.** There is no recovery option — if you lose your password, your file is gone forever.
- Encrypted files are saved with a `.lockit` extension.
- Secure shredding is enabled by default — the original file is permanently deleted after encryption.

---

## 📋 Changelog

### v1.2 *(latest)*
- Added password confirmation for extra security
- Removed hint system (coming back in a future version)

### v1.1
- Added secure file shredding after encryption
- Added right-click context menu integration
- Various improvements

### v1.0
- Initial release 

---

##  Built With

- Python 3
- [cryptography](https://pypi.org/project/cryptography/) library
- tkinter (UI)
- PyInstaller (packaging)

---

## 👤 Author

Made with ❤️ by **Tinnth7**  
*"Hope you still use it. love, Brother."* 🙏
