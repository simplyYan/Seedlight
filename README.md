# Seedlight 🌱🔐

Seedlight is a lightweight, offline desktop application for securely storing and recovering cryptocurrency seed phrases using strong encryption.

It allows users to create encrypted `.seed` files protected by a user-defined password, and later decrypt them locally when needed. No data ever leaves your machine.

---

## Web version
Seedlight has a web version that is fast, lightweight, and even more secure, with state-of-the-art encryption and advanced security mechanisms. You can access it via Github Pages (https://simplyyan.github.io/Seedlight/) or the website hosted on InfinityFree (https://seedlight.42web.io).

## ✨ Features

- 🔐 Strong encryption (AES + HMAC via Fernet)
- 🧠 Password-based key derivation (PBKDF2 + salt)
- 🧅 Multiple encryption layers
- 📁 Encrypted `.seed` file format
- 🖥️ Simple and modern GUI
- 🌐 Fully offline (no network usage)
- 🪶 Lightweight and fast

---

## 🔒 Security Model

Seedlight follows standard cryptographic principles:

- A **user-defined password** (minimum 8 characters) is used to derive an encryption key.
- A **random salt** is generated for each file.
- Key derivation uses **PBKDF2 with SHA-256 and high iteration count**.
- Seed phrases are encrypted locally and never stored in plain text on disk.

> **Important:**  
> Security depends on the strength of the password and the integrity of the user's system.  
> Seedlight is intended for **personal use** and is **not a replacement for hardware wallets or institutional custody solutions**.

---

## 🚀 Usage

### 1. Install dependency

```bash
pip install cryptography
````

### 2. Run Seedlight

```bash
python seedlight.py
```

### 3. Create a `.seed` file

* Enter your seed phrase
* Enter a strong password (8+ characters)
* Click **Save .seed**

### 4. Open a `.seed` file

* Enter the correct password
* Click **Open .seed**
* The seed phrase will be decrypted locally

---

## 📦 File Format

* `.seed` files are binary and encrypted
* They are useless without the correct password
* Files are resistant to tampering (integrity protected)

---

## ⚠️ Disclaimer

This project is provided **as-is**, without warranty of any kind.

* Do **not** use weak passwords
* Do **not** store your only copy of a seed digitally
* Always keep offline backups (e.g. paper, metal)

You are fully responsible for how you use this software.

---

## 📜 License

MIT License — feel free to use, modify, and distribute.

---

## 🤝 Contributions

Issues, audits, and improvements are welcome.
Security-related feedback is especially appreciated
