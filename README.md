# Password Vault

A small, offline desktop password manager for Windows, written in Python with a tkinter interface. Everything is stored in a single encrypted file on your own computer. Nothing is sent over the internet.

## Features

- **Master password login.** One password unlocks the vault. It is never stored anywhere.
- **Add, edit and delete entries.** Each entry has a name, a username or email, and a password.
- **Password generator.** Creates 16-character passwords using lowercase letters, uppercase letters, numbers and the symbols `!@#$%^&*()<>:"`. Every generated password contains at least one character from each group.
- **Browse and search.** A list of all entries with a search bar that filters by name. Passwords are hidden as `**********` until you click **Show**.
- **Copy to clipboard.** Once a password is revealed, **Copy** puts it on the clipboard.
- **Recently deleted.** Deleted entries move to a Recently deleted list instead of disappearing. They stay there until you restore them or permanently delete them. Nothing is ever removed automatically.
- **Change master password.** Re-encrypts the whole vault with a new password.
- **Full encryption at rest.** Names, usernames, passwords and deleted items are all encrypted. See [How the encryption works](#how-the-encryption-works).

## Installation

There are two ways to use Password Vault: run the Python script directly, or build a standalone `.exe` that runs without Python installed.

### 1. Install Python

Download Python 3.10 or newer from [python.org/downloads](https://www.python.org/downloads/) and run the installer.

On the first screen of the installer, tick **"Add python.exe to PATH"** before clicking Install. If you skip this, the commands below will not be found.

Check that it worked by opening PowerShell and running:

```
py --version
```

It should print a version number such as `Python 3.12.6`.

> **Troubleshooting:** If you get "Python was not found", Windows may be redirecting the command to the Microsoft Store. Open **Settings**, search for **Manage app execution aliases**, and turn off the entries for `python.exe` and `python3.exe`. Then close PowerShell and open a new window.

### 2. Download the code

Either clone the repository:

```
git clone https://github.com/<your-username>/<repo-name>.git
cd <repo-name>
```

or download it as a ZIP from GitHub (**Code → Download ZIP**), extract it, and open PowerShell in the extracted folder.

### 3. Install the dependency

Password Vault needs one third-party library, [`cryptography`](https://cryptography.io/), which provides the encryption:

```
py -m pip install cryptography
```

### 4. Run it

```
py password_vault.py
```

The first time it runs, it asks you to create a master password.

### 5. (Optional) Build a standalone .exe

To make a single `PasswordVault.exe` that you can run by double-clicking, and that works on Windows PCs without Python installed, use PyInstaller:

```
py -m pip install pyinstaller
py -m PyInstaller --onefile --windowed --name PasswordVault password_vault.py
```

- `--onefile` bundles everything into one `.exe`.
- `--windowed` stops a black console window opening behind the app.

The finished program is at `dist\PasswordVault.exe`. You can move it anywhere you like. The `build` folder and `PasswordVault.spec` file are temporary and can be deleted.

> **Troubleshooting:** If you see `ERROR: Script file 'password_vault.py' does not exist`, PowerShell is in the wrong folder. Use `cd` to move into the folder that contains `password_vault.py` (run `dir` to check), then run the command again.

When you update `password_vault.py`, run the PyInstaller command again to rebuild the `.exe`.

## Using Password Vault

1. **First launch:** create a master password (at least 8 characters) and type it a second time to confirm.
2. **Later launches:** enter your master password to unlock.
3. From the menu, choose:
   - **New password:** fill in Name, Username / email and Password. Click **Generate** for a random password. **Confirm** becomes clickable once all three boxes are filled.
   - **Browse passwords:** view, search, reveal, copy, edit or delete entries. **Recently deleted** is linked below the list.
   - **Change master password:** enter your current password, then the new one twice.

### Where your data is stored

Your vault is a single file called `vault.dat`. It is created in the same folder as the program: next to `PasswordVault.exe` if you built the exe, or next to `password_vault.py` if you run the script.

- **Keep `vault.dat` next to the program.** If you move the `.exe`, move `vault.dat` with it. If the program can't find `vault.dat`, it assumes this is a first run and offers to create a new, empty vault.
- **Back it up.** Copy `vault.dat` to a USB drive or cloud storage now and then. The file is encrypted, so the backup is as safe as the original.
- **Never commit `vault.dat` to Git.** The included `.gitignore` excludes it. Even though it's encrypted, there's no reason to publish it.

### If you forget your master password

Your passwords **cannot be recovered**. There is no reset option and no back door. This is deliberate: anything that let you recover the vault without the password would also let an attacker do it. If you forget it, delete `vault.dat` and start a new vault.

## How the encryption works

This section describes exactly what happens to your data. The implementation is in the `Vault` class and the `derive_key` function in `password_vault.py`.

### Overview

```
master password ─┐
                 ├─► PBKDF2-HMAC-SHA256 (600,000 rounds) ─► 32-byte key
random salt ─────┘                                              │
                                                                ▼
your entries (JSON) ────────────────────────────────► Fernet (AES + HMAC)
                                                                │
                                                                ▼
                                          vault.dat = salt + encrypted token
```

The design uses two well-established building blocks from the `cryptography` library: **PBKDF2** to turn your password into a key, and **Fernet** to encrypt and authenticate the data. No custom cryptography is involved.

### Step 1: Turning the master password into a key

Encryption algorithms need a key made of random-looking bytes of a fixed length. A human password like `CorrectHorse42` is neither, so it can't be used directly. Instead, it is passed through a **key derivation function**, PBKDF2-HMAC-SHA256:

| Setting | Value | Why |
|---|---|---|
| Hash function | SHA-256 | Widely trusted, standard choice |
| Iterations | 600,000 | Matches the current OWASP recommendation for PBKDF2-SHA256 |
| Salt | 16 random bytes | Makes every vault's key unique |
| Output | 32 bytes | The key size Fernet requires |

**Why 600,000 iterations?** PBKDF2 repeats its hashing step 600,000 times. On a normal computer this takes around half a second, which you barely notice when logging in. An attacker who has stolen `vault.dat` and wants to guess your password must pay the same cost for every guess, which makes guessing billions of passwords impractical.

**Why a salt?** The salt is 16 bytes from the operating system's secure random generator (`os.urandom`), created when a vault is set up. Because every vault has a different salt, two people with the same master password still end up with completely different keys. This also defeats precomputed "rainbow tables" of common passwords. The salt isn't secret; it's stored in plain form at the start of `vault.dat` so it can be read back at login.

The master password itself, and the key derived from it, are **never written to disk**. They exist only in memory while the program is running.

### Step 2: Encrypting the data with Fernet

All vault data (saved entries and Recently deleted entries) is serialised to JSON and encrypted as a single block using [Fernet](https://github.com/fernet/spec/blob/master/Spec.md), a standard recipe for authenticated symmetric encryption. Fernet splits the 32-byte key into two halves:

- **Encryption key (16 bytes):** the data is encrypted with **AES-128 in CBC mode** with PKCS7 padding. A fresh random 16-byte initialisation vector (IV) is generated on every save, so the encrypted output looks completely different each time, even if the data hasn't changed.
- **Signing key (16 bytes):** an **HMAC-SHA256** tag is computed over the encrypted data. The tag acts like a tamper seal that can only be produced with the key. If a single byte of the file changes, whether by corruption or deliberate tampering, the tag no longer matches and the program refuses to decrypt it.

A Fernet token has this layout (the whole thing is base64url-encoded):

| Field | Size | Contents |
|---|---|---|
| Version | 1 byte | Always `0x80` |
| Timestamp | 8 bytes | Time the token was created |
| IV | 16 bytes | Random initialisation vector |
| Ciphertext | variable | Your AES-encrypted data |
| HMAC | 32 bytes | Tamper seal over all of the above |

### Step 3: The vault file

`vault.dat` is simply:

```
[ 16-byte salt ][ Fernet token ]
```

Inside the encrypted token, once decrypted, the data looks like this:

```json
{
  "version": 2,
  "entries": [
    {"name": "Gmail", "username": "me@example.com", "password": "..."}
  ],
  "deleted": [
    {"name": "Old site", "username": "me", "password": "...", "deleted_at": "2026-09-25T14:03:11"}
  ]
}
```

Every field, including entry names and usernames, is inside the encrypted part. Someone looking at `vault.dat` cannot see which sites you have accounts for.

Files are written **atomically**. The new data is written to `vault.dat.tmp` first, then swapped into place in a single operation. If the program crashes or the power goes out mid-save, you keep the previous intact vault instead of a half-written one.

### Step 4: Unlocking

When you enter your master password:

1. The salt is read from the first 16 bytes of `vault.dat`.
2. The key is re-derived from the password you typed and that salt (Step 1).
3. Fernet checks the HMAC tag using the derived key.
4. If the tag matches, the data is decrypted and loaded. If it doesn't, the password was wrong and nothing is decrypted.

This is how the program verifies your password without ever storing it, or a hash of it. The only way to check a password is to try decrypting the vault with it.

### Changing the master password

When you change your master password, the program first verifies the current password by attempting to decrypt the vault with it. It then generates a **new random salt**, derives a new key from the new password, and re-encrypts all data with it. After this, the old password cannot open the vault.

### Password generation

Generated passwords use Python's [`secrets`](https://docs.python.org/3/library/secrets.html) module, which draws from the operating system's cryptographically secure random number generator. It is not the predictable `random` module. The generator:

1. Picks one character from each group (lowercase, uppercase, digit, symbol), so every group is guaranteed to appear.
2. Fills the remaining 12 positions from all 76 characters combined.
3. Shuffles the result with a secure shuffle, so the guaranteed characters aren't always at the start.

## Security notes and limitations

This is a personal project. It uses standard, well-reviewed cryptography, but the program itself has not been independently audited. Be aware of the following:

- **Your master password is the weak point.** The encryption is only as strong as the password. Anyone with a copy of `vault.dat` can try guessing offline. Use a long passphrase, for example four or more random words.
- **Data is decrypted in memory while the app is unlocked.** Python can't reliably wipe strings from memory, so decrypted data may linger in RAM until the program closes. This is normal for most password managers.
- **A compromised computer defeats any password manager.** Malware or a keylogger on your PC could capture your master password as you type it.
- **Copied passwords stay on the clipboard** until you copy something else. If Windows clipboard history (**Win + V**) is turned on, copied passwords are saved there as well.
- **Some metadata is visible without the password:** the size of `vault.dat` (a rough hint of how many entries it holds), and the time the vault was last saved, which is part of the Fernet token.
- **No automatic lock.** The vault stays unlocked until you close the program.

## Project files

| File | Purpose |
|---|---|
| `password_vault.py` | The entire application |
| `README.md` | This file |
| `.gitignore` | Stops `vault.dat` and build output being committed |
| `vault.dat` | Your encrypted vault (created on first run, **not** committed) |

## Requirements

- Windows 10 or 11. The code also runs on macOS and Linux with Python and tkinter installed, but it has been designed and tested for Windows.
- Python 3.10+
- [`cryptography`](https://pypi.org/project/cryptography/)
- [`pyinstaller`](https://pypi.org/project/pyinstaller/), only for building the `.exe`
