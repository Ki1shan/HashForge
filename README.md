# HashForge

**HashForge** is a GUI-based Python toolkit for detecting, generating, and cracking hashes.  
It is designed for cybersecurity learners, penetration testers, and security professionals who want a simple yet powerful way to experiment with cryptographic hashes.

---

## 🎯 Purpose of Building HashForge

1. **Educational Learning**  
   To deeply understand how password hashing, storage, and cracking work in real-world cybersecurity.  
   Many organizations store passwords as hashes; knowing how attackers crack these helps build better defenses.

2. **Hands-On Hacker Tool**  
   To practice and demonstrate dictionary-based hash cracking using popular algorithms (MD5, SHA variants, NTLM, bcrypt, etc.), helping identify weak or compromised passwords.

3. **Security Testing and Auditing**  
   Tools like this help penetration testers and security teams audit password strength and identify vulnerabilities in systems that store hashed passwords.

4. **Foundation for Advanced Development**  
   This tool serves as a base to add more complex cracking methods and tools (brute-force, GPU acceleration, batch operations).

---

## ✨ Features

- 🔍 **Hash Detection**  
  Automatically identifies common hash types such as MD5, SHA1, SHA224, SHA256, SHA384, SHA512, NTLM, bcrypt, and Base64.

- 🗝️ **Hash Cracking**  
  - Supports dictionary-based attacks with custom wordlists  
  - Optional salts for cracking  
  - Mutation rules (capitalize, reverse, leet, upper)  
  - Multi-threaded cracking for responsiveness  

- 🧪 **Password → Hash Generator**  
  Generate test hashes for your own passwords in multiple formats:  
  - MD5, SHA1, SHA224, SHA256, SHA384, SHA512  
  - NTLM  
  - bcrypt  
  - Base64  

- 🖥️ **User-Friendly GUI**  
  Built with Tkinter, HashForge provides a split-pane interface for cracking and generating hashes side by side.

---

### 1. Clone the Repository
```
https://github.com/Ki1shan/HashForge-Project.git
cd HashForge
```
### 2. Install Requirements 
```
  pip3 install bcrypt requests

```
### 3. Run the tool
```
  python3 hashforge.py
```

## ⚖️ Disclaimer

This project is for educational and authorized penetration testing only.
The author is not responsible for misuse of this tool. Always have legal permission before testing any system
