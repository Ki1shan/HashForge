import tkinter as tk
from tkinter import ttk, filedialog, messagebox
import hashlib
import base64
import hmac
import threading
import os
import re
from typing import Optional, Dict, Callable

HASH_PATTERNS = {
    "MD5": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "SHA1": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "SHA224": {
        "length": 56,
        "regex": r"^[a-fA-F0-9]{56}$",
        "charset": "hex"
    },
    "SHA256": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "SHA384": {
        "length": 96,
        "regex": r"^[a-fA-F0-9]{96}$",
        "charset": "hex"
    },
    "SHA512": {
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "charset": "hex"
    },
    "SHA3-224": {
        "length": 56,
        "regex": r"^[a-fA-F0-9]{56}$",
        "charset": "hex"
    },
    "SHA3-256": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "SHA3-384": {
        "length": 96,
        "regex": r"^[a-fA-F0-9]{96}$",
        "charset": "hex"
    },
    "SHA3-512": {
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "charset": "hex"
    },
    "RIPEMD160": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "WHIRLPOOL": {
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "charset": "hex"
    },
    "NTLM": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "MD4": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "MD2": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "GOST": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "SNEFRU": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "SNEFRU256": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "ADLER32": {
        "length": 8,
        "regex": r"^[a-fA-F0-9]{8}$",
        "charset": "hex"
    },
    "CRC32": {
        "length": 8,
        "regex": r"^[a-fA-F0-9]{8}$",
        "charset": "hex"
    },
    "CRC64": {
        "length": 16,
        "regex": r"^[a-fA-F0-9]{16}$",
        "charset": "hex"
    },
    "JENKINS": {
        "length": 8,
        "regex": r"^[a-fA-F0-9]{8}$",
        "charset": "hex"
    },
    "FNV132": {
        "length": 8,
        "regex": r"^[a-fA-F0-9]{8}$",
        "charset": "hex"
    },
    "FNV164": {
        "length": 16,
        "regex": r"^[a-fA-F0-9]{16}$",
        "charset": "hex"
    },
    "MYSTERY": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "MD5-SUM": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "SHA1-SUM": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "SHA256-SUM": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "SHA512-SUM": {
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "charset": "hex"
    },
    "BLAKE2b": {
        "length": 128,
        "regex": r"^[a-fA-F0-9]{128}$",
        "charset": "hex"
    },
    "BLAKE2s": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "BLAKE3": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "MDC2": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "HAVAL-128": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "HAVAL-160": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "HAVAL-192": {
        "length": 48,
        "regex": r"^[a-fA-F0-9]{48}$",
        "charset": "hex"
    },
    "HAVAL-224": {
        "length": 56,
        "regex": r"^[a-fA-F0-9]{56}$",
        "charset": "hex"
    },
    "HAVAL-256": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "TIGER128": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "TIGER160": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "TIGER192": {
        "length": 48,
        "regex": r"^[a-fA-F0-9]{48}$",
        "charset": "hex"
    },
    "PBKDF2-HMAC-SHA256": {
        "length": -1,
        "regex": r"^[a-fA-F0-9]+$",
        "charset": "hex",
        "special": True
    },
    "PBKDF2-HMAC-SHA1": {
        "length": -1,
        "regex": r"^[a-fA-F0-9]+$",
        "charset": "hex",
        "special": True
    },
    "BCRYPT": {
        "length": -1,
        "regex": r"^\$2[ayb]\$\d{2}\$[./A-Za-z0-9]{53}$",
        "charset": "bcrypt"
    },
    "ARGON2": {
        "length": -1,
        "regex": r"^\$argon2[id]\$\d+\$",
        "charset": "argon2"
    },
    "SCRYPT": {
        "length": -1,
        "regex": r"^\$scrypt\$",
        "charset": "scrypt"
    },
    "CRYPT": {
        "length": -1,
        "regex": r"^\$[0-9a-zA-Z]{1,2}\$[./A-Za-z0-9]{11,}$",
        "charset": "crypt"
    },
    "DESCrypt": {
        "length": 13,
        "regex": r"^[./A-Za-z0-9]{13}$",
        "charset": "des"
    },
    "MD5-Crypt": {
        "length": 34,
        "regex": r"^\$1\$[./A-Za-z0-9]{0,8}\$[./A-Za-z0-9]{22}$",
        "charset": "md5crypt"
    },
    "SHA256-Crypt": {
        "length": 63,
        "regex": r"^\$5\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{43}$",
        "charset": "sha256crypt"
    },
    "SHA512-Crypt": {
        "length": 99,
        "regex": r"^\$6\$[./A-Za-z0-9]{0,16}\$[./A-Za-z0-9]{86}$",
        "charset": "sha512crypt"
    },
    "NTLMv2": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "LM": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "Base64": {
        "length": -1,
        "regex": r"^[A-Za-z0-9+/]+=*$",
        "charset": "base64"
    },
    "Base32": {
        "length": -1,
        "regex": r"^[A-Z2-7]+=*$",
        "charset": "base32"
    },
    "Base16": {
        "length": -1,
        "regex": r"^[A-F0-9]+$",
        "charset": "base16"
    },
    "URL-Encoded": {
        "length": -1,
        "regex": r"%[0-9A-Fa-f]{2}",
        "charset": "url"
    },
    "HTML-Entity": {
        "length": -1,
        "regex": r"&#\d+;|&[a-zA-Z]+;",
        "charset": "html"
    },
    "IPv6": {
        "length": -1,
        "regex": r"^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$",
        "charset": "ipv6"
    },
    "UUID": {
        "length": 36,
        "regex": r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$",
        "charset": "uuid"
    },
    "MSSQL": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "MySQL": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "PostgreSQL": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "Oracle": {
        "length": 16,
        "regex": r"^[a-fA-F0-9]{16}$",
        "charset": "hex"
    },
    "Cisco-Type7": {
        "length": -1,
        "regex": r"^021[0-9A-Fa-f]{2}[0-9A-Fa-f]+$",
        "charset": "cisco7"
    },
    "Cisco-PMD5": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "Juniper": {
        "length": 64,
        "regex": r"^[a-fA-F0-9]{64}$",
        "charset": "hex"
    },
    "RACF": {
        "length": 16,
        "regex": r"^[a-fA-F0-9]{16}$",
        "charset": "hex"
    },
    "SAP-B": {
        "length": 16,
        "regex": r"^[a-fA-F0-9]{16}$",
        "charset": "hex"
    },
    "SAP-G": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "DNSSEC": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "CURL": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "WPA": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "NT-CHALLENGE": {
        "length": 16,
        "regex": r"^[a-fA-F0-9]{16}$",
        "charset": "hex"
    },
    "HTTP-Digest": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "SALESFORCE": {
        "length": 40,
        "regex": r"^[a-fA-F0-9]{40}$",
        "charset": "hex"
    },
    "MEDIAWIKI": {
        "length": 32,
        "regex": r"^[a-fA-F0-9]{32}$",
        "charset": "hex"
    },
    "SKIPJACK": {
        "length": 16,
        "regex": r"^[a-fA-F0-9]{16}$",
        "charset": "hex"
    },
}

HASH_ALGORITHMS = {
    "MD5": lambda d: hashlib.md5(d).hexdigest(),
    "SHA1": lambda d: hashlib.sha1(d).hexdigest(),
    "SHA224": lambda d: hashlib.sha224(d).hexdigest(),
    "SHA256": lambda d: hashlib.sha256(d).hexdigest(),
    "SHA384": lambda d: hashlib.sha384(d).hexdigest(),
    "SHA512": lambda d: hashlib.sha512(d).hexdigest(),
    "SHA3-224": lambda d: hashlib.sha3_224(d).hexdigest(),
    "SHA3-256": lambda d: hashlib.sha3_256(d).hexdigest(),
    "SHA3-384": lambda d: hashlib.sha3_384(d).hexdigest(),
    "SHA3-512": lambda d: hashlib.sha3_512(d).hexdigest(),
    "RIPEMD160": lambda d: hashlib.new('ripemd160').hexdigest(),
    "WHIRLPOOL": lambda d: hashlib.new('whirlpool').hexdigest(),
    "NTLM": lambda d: hashlib.new('md4', d.encode('utf-16le')).hexdigest(),
    "MD4": lambda d: hashlib.new('md4').hexdigest(),
    "MD2": lambda d: hashlib.new('md2').hexdigest(),
    "GOST": lambda d: hashlib.new('gost').hexdigest(),
    "SNEFRU": lambda d: hashlib.new('snefru').hexdigest(),
    "SNEFRU256": lambda d: hashlib.new('snefru256').hexdigest(),
    "BLAKE2b": lambda d: hashlib.blake2b(d).hexdigest(),
    "BLAKE2s": lambda d: hashlib.blake2s(d).hexdigest(),
    "MDC2": lambda d: hashlib.new('mdc2').hexdigest(),
    "HAVAL-128": lambda d: hashlib.new('haval128').hexdigest(),
    "HAVAL-160": lambda d: hashlib.new('haval160').hexdigest(),
    "HAVAL-192": lambda d: hashlib.new('haval192').hexdigest(),
    "HAVAL-224": lambda d: hashlib.new('haval224').hexdigest(),
    "HAVAL-256": lambda d: hashlib.new('haval256').hexdigest(),
    "TIGER128": lambda d: hashlib.new('tiger128').hexdigest(),
    "TIGER160": lambda d: hashlib.new('tiger160').hexdigest(),
    "TIGER192": lambda d: hashlib.new('tiger192').hexdigest(),
}

MUTATION_RULES = {
    "None": lambda w: [w],
    "Lowercase": lambda w: [w.lower()],
    "Uppercase": lambda w: [w.upper()],
    "Capitalize": lambda w: [w.capitalize()],
    "Reverse": lambda w: [w[::-1]],
    "Leet": lambda w: [w.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$').replace('t', '7').replace('l', '1').replace('g', '6').replace('b', '8')],
    "Duplicate": lambda w: [w + w],
    "Title Case": lambda w: [w.title()],
    "Swap Case": lambda w: [w.swapcase()],
    "Add Numbers": lambda w: [w + str(i) for i in range(10)],
    "Add Special": lambda w: [w + c for c in "!@#$%^&*"],
    "Year Append": lambda w: [w + str(y) for y in range(1990, 2030)],
}

def compute_hash(plaintext: str, algorithm: str, salt: Optional[str] = None) -> str:
    data = plaintext.encode('utf-8')
    if salt:
        data = salt.encode('utf-8') + data
    
    if algorithm in HASH_ALGORITHMS:
        return HASH_ALGORITHMS[algorithm](data)
    elif algorithm == "Base64":
        return base64.b64encode(data).decode('ascii')
    elif algorithm == "Base32":
        return base64.b32encode(data).decode('ascii')
    elif algorithm == "Base16":
        return base64.b16encode(data).decode('ascii')
    return ""

def detect_hash_type(hash_value: str) -> list:
    hash_value = hash_value.strip()
    detected = []
    length = len(hash_value)
    
    for hash_type, info in HASH_PATTERNS.items():
        if info["charset"] == "hex" and info["length"] == length:
            if re.match(info["regex"], hash_value, re.IGNORECASE):
                detected.append(hash_type)
        elif info["charset"] in ["bcrypt", "argon2", "scrypt", "crypt", "des", "md5crypt", "sha256crypt", "sha512crypt"]:
            if re.match(info["regex"], hash_value):
                detected.append(hash_type)
        elif info["charset"] == "base64":
            if re.match(info["regex"], hash_value) and len(hash_value) >= 4:
                detected.append(hash_type)
        elif info["charset"] == "base32":
            if re.match(info["regex"], hash_value, re.IGNORECASE):
                detected.append(hash_type)
        elif info["charset"] == "base16":
            if re.match(info["regex"], hash_value, re.IGNORECASE):
                detected.append(hash_type)
        elif info["charset"] in ["uuid", "url", "html", "ipv6"]:
            if re.match(info["regex"], hash_value):
                detected.append(hash_type)
    
    if not detected:
        detected = ["Unknown"]
    
    return detected[:10]

def apply_mutations(word: str, rules: list) -> list:
    variants = [word]
    for rule in rules:
        if rule in MUTATION_RULES:
            new_variants = []
            for v in variants:
                new_variants.extend(MUTATION_RULES[rule](v))
            variants = new_variants
    return variants

class HashForgeGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HashForge - Hash Cracking & Generation Tool")
        self.root.geometry("1100x700")
        self.crack_thread = None
        self.stop_crack = False
        
        self.setup_ui()
    
    def setup_ui(self):
        main_paned = ttk.PanedWindow(self.root, orient=tk.HORIZONTAL)
        main_paned.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        
        crack_frame = ttk.LabelFrame(main_paned, text="Hash Cracking", padding=10)
        main_paned.add(crack_frame, weight=2)
        
        generate_frame = ttk.LabelFrame(main_paned, text="Hash Generation", padding=10)
        main_paned.add(generate_frame, weight=1)
        
        self.setup_crack_panel(crack_frame)
        self.setup_generate_panel(generate_frame)
    
    def setup_crack_panel(self, parent):
        input_frame = ttk.Frame(parent)
        input_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(input_frame, text="Hash:").pack(side=tk.LEFT)
        self.hash_entry = ttk.Entry(input_frame, width=50)
        self.hash_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        self.hash_entry.bind("<KeyRelease>", self.on_hash_input)
        
        self.detected_label = ttk.Label(parent, text="Detected: ", foreground="blue")
        self.detected_label.pack(fill=tk.X, pady=2)
        
        options_frame = ttk.Frame(parent)
        options_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(options_frame, text="Hash Type:").pack(side=tk.LEFT)
        self.hash_type_combo = ttk.Combobox(options_frame, values=["Auto Detect"] + list(HASH_PATTERNS.keys()), state="readonly", width=20)
        self.hash_type_combo.current(0)
        self.hash_type_combo.pack(side=tk.LEFT, padx=5)
        
        ttk.Label(options_frame, text="Salt:").pack(side=tk.LEFT, padx=(20, 5))
        self.salt_entry = ttk.Entry(options_frame, width=20)
        self.salt_entry.pack(side=tk.LEFT)
        
        ttk.Label(options_frame, text="Mutations:").pack(side=tk.LEFT, padx=(20, 5))
        self.mutations_combo = ttk.Combobox(options_frame, values=list(MUTATION_RULES.keys()), state="readonly", width=15)
        self.mutations_combo.current(0)
        self.mutations_combo.pack(side=tk.LEFT)
        
        wordlist_frame = ttk.Frame(parent)
        wordlist_frame.pack(fill=tk.X, pady=5)
        
        ttk.Label(wordlist_frame, text="Wordlist:").pack(side=tk.LEFT)
        self.wordlist_entry = ttk.Entry(wordlist_frame, width=40)
        self.wordlist_entry.pack(side=tk.LEFT, padx=5, fill=tk.X, expand=True)
        
        browse_btn = ttk.Button(wordlist_frame, text="Browse", command=self.browse_wordlist)
        browse_btn.pack(side=tk.LEFT, padx=5)
        
        self.progress = ttk.Progressbar(parent, mode='determinate')
        self.progress.pack(fill=tk.X, pady=5)
        
        self.status_label = ttk.Label(parent, text="Ready")
        self.status_label.pack(fill=tk.X)
        
        btn_frame = ttk.Frame(parent)
        btn_frame.pack(fill=tk.X, pady=10)
        
        self.crack_btn = ttk.Button(btn_frame, text="Start Cracking", command=self.start_crack)
        self.crack_btn.pack(side=tk.LEFT, padx=5)
        
        self.stop_btn = ttk.Button(btn_frame, text="Stop", command=self.stop_crack_action, state=tk.DISABLED)
        self.stop_btn.pack(side=tk.LEFT, padx=5)
        
        result_frame = ttk.LabelFrame(parent, text="Results", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True, pady=5)
        
        self.result_text = tk.Text(result_frame, height=10, wrap=tk.WORD)
        self.result_text.pack(fill=tk.BOTH, expand=True)
    
    def setup_generate_panel(self, parent):
        ttk.Label(parent, text="Plaintext Password:").pack(fill=tk.X)
        
        gen_input_frame = ttk.Frame(parent)
        gen_input_frame.pack(fill=tk.X, pady=5)
        
        self.gen_password_entry = ttk.Entry(gen_input_frame, width=30, show="*")
        self.gen_password_entry.pack(side=tk.LEFT, fill=tk.X, expand=True)
        
        toggle_btn = ttk.Button(gen_input_frame, text="Show", command=self.toggle_password_visibility)
        toggle_btn.pack(side=tk.LEFT, padx=5)
        
        gen_btn = ttk.Button(parent, text="Generate Hashes", command=self.generate_hashes)
        gen_btn.pack(pady=5)
        
        result_frame = ttk.LabelFrame(parent, text="Generated Hashes", padding=5)
        result_frame.pack(fill=tk.BOTH, expand=True)
        
        self.gen_result_text = tk.Text(result_frame, height=15, wrap=tk.WORD)
        self.gen_result_text.pack(fill=tk.BOTH, expand=True)
    
    def on_hash_input(self, event=None):
        hash_val = self.hash_entry.get().strip()
        if len(hash_val) >= 8:
            detected = detect_hash_type(hash_val)
            self.detected_label.config(text=f"Detected: {', '.join(detected)}")
            if len(detected) == 1 and detected[0] != "Unknown":
                idx = list(HASH_PATTERNS.keys()).index(detected[0]) + 1
                self.hash_type_combo.current(idx)
        else:
            self.detected_label.config(text="Detected: ")
    
    def browse_wordlist(self):
        filename = filedialog.askopenfilename(title="Select Wordlist", filetypes=[("Text Files", "*.txt"), ("All Files", "*.*")])
        if filename:
            self.wordlist_entry.delete(0, tk.END)
            self.wordlist_entry.insert(0, filename)
    
    def toggle_password_visibility(self):
        current = self.gen_password_entry.cget('show')
        self.gen_password_entry.config(show="" if current == "*" else "*")
    
    def start_crack(self):
        hash_val = self.hash_entry.get().strip()
        if not hash_val:
            messagebox.showerror("Error", "Please enter a hash value")
            return
        
        wordlist = self.wordlist_entry.get().strip()
        if not wordlist or not os.path.exists(wordlist):
            messagebox.showerror("Error", "Please select a valid wordlist file")
            return
        
        hash_type = self.hash_type_combo.get()
        salt = self.salt_entry.get().strip() or None
        mutation = self.mutations_combo.get()
        
        if hash_type == "Auto Detect":
            detected_types = detect_hash_type(hash_val)
            if detected_types[0] != "Unknown":
                hash_type = detected_types[0]
            else:
                messagebox.showerror("Error", "Could not detect hash type. Please select manually.")
                return
        
        self.result_text.delete(1.0, tk.END)
        self.result_text.insert(tk.END, f"Starting crack with {hash_type}...\n")
        self.result_text.insert(tk.END, f"Wordlist: {wordlist}\n")
        self.result_text.insert(tk.END, f"Mutation: {mutation}\n")
        if salt:
            self.result_text.insert(tk.END, f"Salt: {salt}\n")
        self.result_text.insert(tk.END, "-" * 50 + "\n")
        
        self.crack_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.stop_crack = False
        self.progress.config(value=0)
        
        self.crack_thread = threading.Thread(target=self.crack_worker, args=(hash_val, wordlist, hash_type, salt, mutation))
        self.crack_thread.start()
    
    def crack_worker(self, target_hash, wordlist, hash_type, salt, mutation):
        try:
            file_size = os.path.getsize(wordlist)
            processed = 0
            matches = 0
            
            with open(wordlist, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    if self.stop_crack:
                        break
                    
                    word = line.strip()
                    if not word:
                        continue
                    
                    variants = apply_mutations(word, [mutation]) if mutation != "None" else [word]
                    
                    for variant in variants:
                        computed = compute_hash(variant, hash_type, salt)
                        processed += 1
                        
                        if computed.lower() == target_hash.lower():
                            self.root.after(0, self.crack_success, variant, processed)
                            return
                        
                        if computed == target_hash:
                            self.root.after(0, self.crack_success, variant, processed)
                            return
                    
                    if processed % 100 == 0:
                        progress = min(100, (processed / 10000) * 100)
                        self.root.after(0, lambda p=progress: self.progress.config(value=p))
            
            self.root.after(0, self.crack_complete, processed)
        
        except Exception as e:
            self.root.after(0, lambda: self.crack_error(str(e)))
    
    def crack_success(self, password, count):
        self.result_text.insert(tk.END, f"\n*** PASSWORD FOUND! ***\n")
        self.result_text.insert(tk.END, f"Password: {password}\n")
        self.result_text.insert(tk.END, f"Attempts: {count}\n")
        self.status_label.config(text="CRACKED!", foreground="green")
        self.crack_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
        self.progress.config(value=100)
        messagebox.showinfo("Success", f"Password found: {password}")
    
    def crack_complete(self, count):
        self.result_text.insert(tk.END, f"\nNo match found after {count} attempts.\n")
        self.status_label.config(text="Complete - No match", foreground="red")
        self.crack_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def crack_error(self, error):
        self.result_text.insert(tk.END, f"\nError: {error}\n")
        self.status_label.config(text="Error", foreground="red")
        self.crack_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)
    
    def stop_crack_action(self):
        self.stop_crack = True
        self.status_label.config(text="Stopping...")
    
    def generate_hashes(self):
        password = self.gen_password_entry.get()
        if not password:
            messagebox.showerror("Error", "Please enter a password")
            return
        
        self.gen_result_text.delete(1.0, tk.END)
        self.gen_result_text.insert(tk.END, f"Hashes for: {password}\n")
        self.gen_result_text.insert(tk.END, "=" * 60 + "\n\n")
        
        for algo in sorted(HASH_ALGORITHMS.keys()):
            try:
                hash_val = compute_hash(password, algo)
                self.gen_result_text.insert(tk.END, f"{algo:20} : {hash_val}\n")
            except Exception as e:
                self.gen_result_text.insert(tk.END, f"{algo:20} : Error - {str(e)}\n")
        
        try:
            b64 = compute_hash(password, "Base64")
            self.gen_result_text.insert(tk.END, f"{'Base64':20} : {b64}\n")
        except:
            pass
        
        try:
            b32 = compute_hash(password, "Base32")
            self.gen_result_text.insert(tk.END, f"{'Base32':20} : {b32}\n")
        except:
            pass

def main():
    root = tk.Tk()
    app = HashForgeGUI(root)
    root.mainloop()

if __name__ == "__main__":
    main()
