# LockIt
File/Folder locker!
LockIt Pro User Guide
How LockIt Pro Works

LockIt Pro protects your sensitive files and folders using strong AES-256-GCM encryption. This is the same standard used by governments and security professionals worldwide.
Encryption Process

When you lock a file:

    A random salt (16 bytes) and a random nonce (12 bytes) are generated for each file.        

    Your password is stretched with PBKDF2 (200,000 iterations of SHA-256) to create a 256-bit encryption key.

    The file is encrypted in 1 MB chunks (efficient for large files) and an authentication tag is added to detect tampering.

    A magic header LOCKITv1 is written at the beginning of the output file to identify it as a LockIt‑encrypted file.

    The encrypted file gets the extension .lockit. The original file is securely deleted.

Decryption Process

When you unlock a file:

    LockIt Pro reads the magic header to verify the file is a valid LockIt file.

    The salt and nonce are extracted, and the same PBKDF2 process regenerates the encryption key from your password.

    The file is decrypted chunk by chunk. If the password is wrong or the file has been altered, the authentication tag will fail and decryption will abort with a clear error message.

Folder Mode

When you lock a folder, LockIt Pro walks through every subfolder and encrypts each file individually (keeping the folder structure intact). Already locked files (those containing the magic header) are skipped to avoid double encryption.
How to Use LockIt Pro
System Requirements

    Windows (the .exe version) or any OS with Python 3.6+ (if running from source)

    No additional software or drivers needed

Starting the Application

Double-click LockItPro.exe. The main window will appear with the following sections:

    Operation Mode – choose File or Folder.

    Target – the file or folder you want to lock or unlock.

    Password – enter your password (you can check "Show password" to see what you type).

    LOCK and UNLOCK buttons.

Locking a File

    Select File mode.

    Click Browse and choose the file you want to encrypt.

    Enter a strong password (at least 8 characters, mix of letters, numbers, and symbols).

    Click LOCK.

    A progress bar will spin. The original file disappears, and a new file with the same name plus .lockit appears in the same folder.

    The path field automatically updates to show the new .lockit file.

Unlocking a File

    Select File mode.

    Click Browse and choose the .lockit file you want to decrypt. (You can also browse to any file that was encrypted with LockIt Pro – the magic header is detected even if the extension was changed.)

    Enter the same password you used to lock the file.

    Click UNLOCK.

    The .lockit file disappears, and the original file is restored.

Locking a Folder

    Select Folder mode.

    Click Browse and choose the folder containing files you want to encrypt.

    Enter a password.

    Click LOCK.

    LockIt Pro will encrypt every file inside that folder and all subfolders. Each encrypted file will have a .lockit extension. The original files are deleted.

    The folder itself remains; only the contents are encrypted.

Unlocking a Folder

    Select Folder mode.

    Click Browse and choose the folder containing .lockit files (or a mix of locked and unlocked files – the program will only decrypt those that are encrypted).

    Enter the password used when locking.

    Click UNLOCK.

    All .lockit files in that folder and its subfolders are decrypted back to their original names and contents.

Tips and Important Notes

    Always remember your password – There is no backdoor or password recovery. If you forget the password, your data is permanently lost.

    Keep backups – LockIt Pro deletes the original file immediately after successful encryption. Make sure you have a backup if the data is critical.

    Password strength – Use a password that is long and unique. Avoid common words or personal information.

    Locked files are portable – You can copy, email, or store .lockit files anywhere. Only someone with the correct password can unlock them.

    No cloud dependency – Everything works offline; your data never leaves your computer.

    Large folders – Encrypting a folder with many large files may take several minutes. The progress bar will spin, and the interface stays responsive because the work runs in a background thread.

Error Messages and What They Mean
Message	Meaning
This file is already encrypted	You tried to lock a file that already contains the LockIt magic header. Use Unlock instead.
Incorrect password or corrupted file	The password you entered does not match the one used to encrypt the file, or the .lockit file has been modified.
This file is not a valid LockIt encrypted file	The selected file does not start with the expected magic header. It may be a regular file or a corrupted lock file.
Password cannot be empty	You must enter a password before locking or unlocking.
Please select a file or folder first	You clicked LOCK or UNLOCK without browsing to a target.
Uninstalling

Because LockIt Pro is a standalone .exe, uninstalling is simply deleting the LockItPro.exe file. No registry entries or system files are created.
