# 🔐 HashForge

**HashForge** is a Python-based hash analysis and testing toolkit designed for **educational and authorized penetration testing purposes**. It helps in understanding password security, hashing mechanisms, and common attack techniques like dictionary and brute-force attacks.

---

## 🚀 Features

* 🔍 **Hash Detection** – Identify possible hash algorithms based on patterns and length
* 📖 **Dictionary Attack** – Test hashes using wordlists
* 💨 **Brute Force Attack** – Generate combinations to match hashes
* ⚡ **Multi-Processing** – Utilizes CPU cores for faster execution
* 🌐 **Web Dashboard** – Monitor attack progress via browser
* 📂 **Batch Processing** – Handle multiple hashes at once

---

## 🧠 Supported Algorithms

HashForge supports commonly used hashing algorithms including:

* MD5, SHA1, SHA256, SHA512
* NTLM, LM
* bcrypt, PBKDF2 (basic support)
* Base64, Hex encoding

> Note: Focus is on understanding hashing concepts rather than replicating specialized tools like Hashcat.

---

## 🛠️ Tech Stack

* **Language:** Python
* **Backend:** Flask (for web interface)
* **Libraries:** multiprocessing, hashlib, bcrypt
* **Optional:** argon2, pyopencl (experimental support)

---

## ⚙️ Installation

```bash
# Clone the repository
git clone https://github.com/Ki1shan/HashForge-Project.git
cd HashForge-Project

# Install dependencies
pip install -r requirements.txt
```

---

## ▶️ Usage

### 🔹 Run CLI Mode

```bash
python hashforge.py
```

### 🔹 Run Web Dashboard

```bash
python hashforge.py --web
# Open http://127.0.0.1:5000
```

---

## 📌 Example Commands

```bash
# Detect hash type
python hashforge.py -d <hash>

# Dictionary attack
python hashforge.py -h <hash> -w wordlist.txt

# Brute force
python hashforge.py -h <hash> --brute

# Generate hash
python hashforge.py -g password123
```

---

## 🎯 Learning Objectives

This project was built to:

* Understand how hashing algorithms work
* Learn password cracking techniques used in security testing
* Explore performance optimization using multiprocessing
* Gain practical exposure to cybersecurity concepts

---

## ⚠️ Disclaimer

This tool is developed **strictly for educational and authorized security testing purposes**.

* Do not use on systems without permission
* Unauthorized use may be illegal
* The author is not responsible for misuse

---

## 📜 License

MIT License

---

## 👨‍💻 Author

**Kishan N**
Cybersecurity Enthusiast | Penetration Testing | API Security

GitHub: https://github.com/Ki1shan
