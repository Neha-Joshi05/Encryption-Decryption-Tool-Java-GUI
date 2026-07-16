# 🔐 Encryption / Decryption Tool — Java GUI + Flask Dashboard

> A full-stack encryption application built with Java (AES-256-GCM desktop app)
> and Python Flask (live web dashboard) — using industry-standard authenticated
> encryption with PBKDF2 key derivation. Deployed live on Render.

![Java](https://img.shields.io/badge/Java-17+-orange)
![Python](https://img.shields.io/badge/Python-3.8+-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-green)
![AES](https://img.shields.io/badge/Encryption-AES--256--GCM-red)
![Status](https://img.shields.io/badge/Status-Live-success)

---

## 🌐 Live Demo

👉 **[https://encryption-decryption-tool.onrender.com](https://encryption-decryption-tool-java-gui.onrender.com)**

---

## 🎯 Objective

Build a complete encryption/decryption application that allows users
to encrypt and decrypt text using a password — demonstrating applied
cryptography, key derivation, authenticated encryption, Java GUI
development, and full-stack deployment.

---

## 📖 What is Encryption?

**Simple explanation:**
Encryption converts readable text (plaintext) into unreadable
scrambled data (ciphertext) using a secret key. Only someone
with the correct key can reverse it back to the original text.

**Technical explanation:**
This tool uses AES-256-GCM — a symmetric authenticated encryption
algorithm. The user's password is never used directly as the key.
Instead, PBKDF2-HMAC-SHA256 derives a 256-bit AES key from the
password combined with a randomly generated 16-byte salt. A random
12-byte IV ensures the same text encrypted twice produces completely
different ciphertext. The 128-bit GCM authentication tag detects
any tampering — a wrong password or modified ciphertext causes
immediate decryption failure with no false output.

---

## 🔄 Workflow

```
User enters text + password
          ↓
PBKDF2 derives 256-bit AES key
(password + random 16-byte salt, 120,000 iterations)
          ↓
AES-256-GCM encrypts data
(random 12-byte IV, 128-bit auth tag)
          ↓
Binary packet assembled:
MAGIC | VERSION | SALT | IV | CIPHERTEXT+TAG
          ↓
Base64 encoded → safe to copy and share
          ↓
─────────── Decryption ───────────
          ↓
Base64 decoded → binary packet
          ↓
Salt + IV extracted from packet
          ↓
PBKDF2 re-derives key from password + salt
          ↓
AES-GCM decrypts + verifies auth tag
          ↓
Wrong password → Authentication Failed ❌
Correct password → Original text restored ✅
```

---

## ✨ Features

- 🔒 **AES-256-GCM** — authenticated encryption (detects tampering)
- 🔑 **PBKDF2-HMAC-SHA256** — password-based key derivation
- 🎲 **Random Salt + IV** — every encryption is unique
- ✅ **Authentication Tag** — wrong password = instant failure
- 📋 **Base64 Output** — easy to copy, share, and store
- 💻 **Java Desktop App** — dark theme Swing GUI
- 🌐 **Flask Web Dashboard** — live deployed on Render
- 🔐 **Cross-language** — Java and Python use same binary format
- 💪 **Password Strength Indicator** — real-time feedback
- 🗑️ **Clear + Copy** — user-friendly controls

---

## 🏭 Industry Relevance

This project demonstrates the same cryptography concepts used in:

| Industry | Application |
|---|---|
| **Messaging Apps** | Signal, WhatsApp end-to-end encryption |
| **Banking** | Transaction security, card data protection |
| **Password Managers** | Vault encryption (1Password, Bitwarden) |
| **Healthcare** | Patient data protection (HIPAA compliance) |
| **Cloud Storage** | File encryption at rest (AWS S3, Google Drive) |
| **Enterprise** | Secure file sharing, credential protection |

---

## 🛠️ Tech Stack

| Layer | Technology |
|---|---|
| Desktop App | Java 17, Java Swing, AWT |
| Cryptography (Java) | javax.crypto, AES-GCM, PBKDF2 |
| Web Backend | Python 3, Flask |
| Cryptography (Python) | cryptography library (hazmat) |
| Frontend | HTML, CSS, JavaScript |
| Deployment | Render (free tier) |
| Version Control | Git + GitHub |

---

## 🔬 Security Specification

| Parameter | Value |
|---|---|
| **Algorithm** | AES-256-GCM |
| **Key Size** | 256 bits |
| **Key Derivation** | PBKDF2-HMAC-SHA256 |
| **Iterations** | 120,000 |
| **Salt** | 16 bytes (cryptographically random) |
| **IV / Nonce** | 12 bytes (cryptographically random) |
| **Auth Tag** | 128 bits (GCM) |
| **Output Format** | Base64 encoded binary packet |

### Binary Packet Format

```
┌─────────┬─────────┬──────────┬─────────┬────────┬─────┬──────────────────┐
│ MAGIC   │ VERSION │ SALT_LEN │  IV_LEN │  SALT  │ IV  │ CIPHERTEXT + TAG │
│ 4 bytes │ 1 byte  │  1 byte  │ 1 byte  │ 16 b   │ 12b │   variable       │
└─────────┴─────────┴──────────┴─────────┴────────┴─────┴──────────────────┘
```

---

## 📁 Folder Structure

```
Encryption-Decryption-Tool-Java-GUI/
│
├── java_app/
│   └── EncryptorApp.java        ← Java Swing desktop app
│
├── dashboard/
│   ├── app.py                   ← Flask web server
│   ├── crypto_utils.py          ← Python AES-GCM crypto logic
│   └── templates/
│       └── index.html           ← Web dashboard UI
│
├── data/                        ← Sample test files
├── docs/                        ← Architecture diagrams
├── screenshots/                 ← Proof of work images
├── outputs/                     ← Sample encrypted outputs
│
├── requirements.txt             ← Python dependencies
├── Procfile                     ← Render deployment config
├── .gitignore
└── README.md
```

---

## 🚀 How to Run

### Option A — Web Dashboard (Flask)

```bash
# Clone the repo
git clone https://github.com/Neha-Joshi05/Encryption-Decryption-Tool-Java-GUI.git
cd Encryption-Decryption-Tool-Java-GUI

# Install dependencies
pip install -r requirements.txt

# Run the dashboard
python dashboard/app.py

# Open in browser
http://localhost:5000
```

### Option B — Java Desktop App

```bash
# Navigate to java_app folder
cd java_app

# Compile
javac EncryptorApp.java

# Run
java EncryptorApp
```

### Option C — IntelliJ IDEA

1. Open IntelliJ IDEA → **File → New → Project from Existing Sources**
2. Select the `java_app` folder
3. Set Java version to **17 or higher**
4. Right-click `EncryptorApp.java` → **Run**

---

## 🧪 Sample Test Cases

| Test | Input | Password | Expected Result |
|---|---|---|---|
| Valid encrypt | `Hello World` | `secret123` | Base64 ciphertext |
| Valid decrypt | (above ciphertext) | `secret123` | `Hello World` |
| Wrong password | (above ciphertext) | `wrongpass` | Authentication Failed ❌ |
| Empty text | `` | `secret123` | Input text is empty ❌ |
| Empty password | `Hello` | `` | Password is empty ❌ |
| Special chars | `हेलो @#$%` | `pass` | Encrypts correctly ✅ |
| Long text | 10,000 chars | `pass` | Encrypts correctly ✅ |

---

## 📊 Sample Output

**Input:**
```
Hello, this is a secret message!
```

**Password:** `mypassword123`

**Encrypted Output (Base64):**
```
RU5DUgEQDAAAAP8k9mNx2Kj3lMn7Qp1Zw4Vb6Yt8Xu0Rs2Ow
5Pf3Hg9Ik7Jm1Nl4Qr6St8Uv0Wx2Yz4Ab6Cd8Ef0Gh2Ij4Kl...
```

**Decrypted Output:**
```
Hello, this is a secret message!
```

---


## 🔮 Future Improvements

- Add file encryption/decryption to the web dashboard
- Drag-and-drop file support
- RSA asymmetric encryption option
- Digital signatures for document verification
- Password strength enforcement (minimum requirements)
- QR code for encrypted output sharing
- Dark/Light theme toggle
- Activity log (without storing passwords)
- Mobile-responsive layout improvements
- Package Java app as executable `.jar`

---

## 🎓 Learning Outcomes

- Applied cryptography (AES-GCM, PBKDF2, IV, Salt)
- Java Swing GUI development and event handling
- Cross-language compatibility (Java ↔ Python)
- Flask REST API design
- Full-stack web development and deployment
- Security-first software engineering principles
- Exception handling for cryptographic failures
- Base64 encoding for binary-to-text conversion



---

## ⚠️ Security Disclaimer

This tool is built for **educational and personal use only**.
- Do not use for encrypting highly sensitive data in production
  without a proper security audit
- Never share your encryption password
- Passwords and keys are never stored or transmitted
- This is a student project demonstrating cryptographic concepts

---

## 👤 Author

**Neha Joshi**

- GitHub: https://github.com/Neha-Joshi05/Encryption-Decryption-Tool-Java-GUI.git
- LindkIn : https://www.linkedin.com/in/neha-joshi-0851a2322?utm_source=share_via&utm_content=profile&utm_medium=member_android
---

