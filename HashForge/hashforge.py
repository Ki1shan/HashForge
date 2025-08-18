import tkinter as tk
from tkinter import filedialog, ttk
import hashlib
import re
import base64
import bcrypt
import threading

def detect_hash_type(hash_str):
    hash_str = hash_str.strip()
    hash_lower = hash_str.lower()

    if re.fullmatch(r'[a-f0-9]{32}', hash_lower):
        return 'MD5/NTLM'
    elif re.fullmatch(r'[a-f0-9]{40}', hash_lower):
        return 'SHA1'
    elif re.fullmatch(r'[a-f0-9]{56}', hash_lower):
        return 'SHA224'
    elif re.fullmatch(r'[a-f0-9]{64}', hash_lower):
        return 'SHA256'
    elif re.fullmatch(r'[a-f0-9]{96}', hash_lower):
        return 'SHA384'
    elif re.fullmatch(r'[a-f0-9]{128}', hash_lower):
        return 'SHA512'
    elif hash_str.startswith("$2a$") or hash_str.startswith("$2b$") or hash_str.startswith("$2y$"):
        return 'bcrypt'
    elif re.fullmatch(r'[A-Za-z0-9+/=]+', hash_str) and not re.fullmatch(r'[a-f0-9]+', hash_lower):
        return 'Base64'
    else:
        return 'Unknown'

def hash_compare(input_string, hash_to_crack, hash_type, salt=None):
    try:
        if hash_type == "Base64":
            encoded = base64.b64encode(input_string.encode()).decode()
            return encoded == hash_to_crack

        if salt:
            combo = salt + input_string
        else:
            combo = input_string

        if hash_type == "bcrypt":
            return bcrypt.checkpw(combo.encode(), hash_to_crack.encode())

        hashed = None
        if hash_type == "MD5":
            hashed = hashlib.md5(combo.encode()).hexdigest()
        elif hash_type == "NTLM":
            hashed = hashlib.new('md4', combo.encode('utf-16le')).hexdigest()
        elif hash_type == "SHA1":
            hashed = hashlib.sha1(combo.encode()).hexdigest()
        elif hash_type == "SHA224":
            hashed = hashlib.sha224(combo.encode()).hexdigest()
        elif hash_type == "SHA256":
            hashed = hashlib.sha256(combo.encode()).hexdigest()
        elif hash_type == "SHA384":
            hashed = hashlib.sha384(combo.encode()).hexdigest()
        elif hash_type == "SHA512":
            hashed = hashlib.sha512(combo.encode()).hexdigest()
        else:
            return False

        return hashed.lower() == hash_to_crack.lower()
    except Exception:
        return False

def apply_rules(word, ruleset):
    results = set()
    for rule in ruleset:
        if rule == "capitalize":
            results.add(word.capitalize())
        elif rule == "upper":
            results.add(word.upper())
        elif rule == "reverse":
            results.add(word[::-1])
        elif rule == "leet":
            s = word.replace('a', '4').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '5')
            results.add(s)
    return list(results)

def crack_hash(hash_to_crack, wordlist_path, hash_type, output_callback, salt=None, ruleset=None):
    try:
        found = False
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as file:
            for line in file:
                word = line.strip()
                mutated_words = [word]
                if ruleset:
                    mutated_words += apply_rules(word, ruleset)
                for test_word in mutated_words:
                    if hash_compare(test_word, hash_to_crack, hash_type, salt):
                        output_callback(f"✅ Hash cracked! Plaintext: {test_word}")
                        found = True
                        break
                if found:
                    break
        if not found:
            output_callback("❌ No match found in the wordlist.")
    except FileNotFoundError:
        output_callback("❗ Wordlist file not found.")
    except Exception as e:
        output_callback(f"❗ Error: {e}")

def generate_hashes(password):
    hashes = {
        "MD5": hashlib.md5(password.encode()).hexdigest(),
        "SHA1": hashlib.sha1(password.encode()).hexdigest(),
        "SHA224": hashlib.sha224(password.encode()).hexdigest(),
        "SHA256": hashlib.sha256(password.encode()).hexdigest(),
        "SHA384": hashlib.sha384(password.encode()).hexdigest(),
        "SHA512": hashlib.sha512(password.encode()).hexdigest(),
        "NTLM": hashlib.new('md4', password.encode('utf-16le')).hexdigest(),
        "Base64 (UTF-8)": base64.b64encode(password.encode()).decode(),
        "bcrypt (12 rounds)": bcrypt.hashpw(password.encode(), bcrypt.gensalt(12)).decode()
    }
    return hashes

class HashBreakerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("HashForge")
        self.wordlist_path = ""

        paned = ttk.Panedwindow(self.root, orient=tk.HORIZONTAL)
        paned.pack(fill=tk.BOTH, expand=True)

        main_frame = tk.Frame(paned)
        paned.add(main_frame, weight=3)

        tk.Label(main_frame, text="Enter Hash to Crack:", font=("Arial", 12)).pack(pady=(10, 2))
        self.hash_entry = tk.Entry(main_frame, width=64)
        self.hash_entry.pack()

        detect_frame = tk.Frame(main_frame)
        detect_frame.pack()
        tk.Button(detect_frame, text="Detect Hash Type", command=self.detect_hash).pack(side=tk.LEFT, padx=2)
        self.detected_label = tk.Label(detect_frame, text="Hash Type: Unknown", font=("Arial", 10, "bold"))
        self.detected_label.pack(side=tk.LEFT, padx=8)
        self.hash_type_override = tk.StringVar(main_frame)
        self.hash_type_dropdown = tk.OptionMenu(main_frame, self.hash_type_override, "")
        self.hash_type_dropdown.pack()

        tk.Label(main_frame, text="Salt (leave blank if unsalted):").pack()
        self.salt_entry = tk.Entry(main_frame, width=24)
        self.salt_entry.pack()

        tk.Label(main_frame, text="Mutation Rules (capitalize, upper, reverse, leet; comma-separated):").pack(pady=(6,1))
        self.rules_entry = tk.Entry(main_frame, width=45)
        self.rules_entry.pack()

        file_frame = tk.Frame(main_frame)
        file_frame.pack(pady=(7,2))
        tk.Button(file_frame, text="Select Wordlist", command=self.load_wordlist).pack(side=tk.LEFT, padx=2)
        self.wordlist_label = tk.Label(file_frame, text="", font=("Arial", 8))
        self.wordlist_label.pack(side=tk.LEFT, padx=4)

        tk.Button(main_frame, text="Crack Hash", command=self.crack_threaded).pack(pady=4)

        self.output_text = tk.Text(main_frame, height=16, width=80)
        self.output_text.pack(pady=6)

        gen_frame = tk.LabelFrame(paned, text="Password → Hash Generator", padx=10, pady=10)
        paned.add(gen_frame, weight=1)

        tk.Label(gen_frame, text="Enter password to hash:").pack()
        self.gen_entry = tk.Entry(gen_frame, width=25)
        self.gen_entry.pack()
        tk.Button(gen_frame, text="Generate Hashes", command=self.generate_hashes).pack(pady=3)
        self.gen_output = tk.Text(gen_frame, height=15, width=55)
        self.gen_output.pack(pady=3)

    def load_wordlist(self):
        self.wordlist_path = filedialog.askopenfilename()
        self.wordlist_label.config(text=f"Loaded: {self.wordlist_path.split('/')[-1]}")
        self.output(f"📂 Loaded wordlist: {self.wordlist_path}")

    def detect_hash(self):
        hash_value = self.hash_entry.get().strip()
        hash_type = detect_hash_type(hash_value)
        self.detected_label.config(text=f"Hash Type: {hash_type}")

        options = []
        if hash_type == "MD5/NTLM":
            options = ["MD5", "NTLM"]
        elif hash_type == "Unknown":
            options = ["MD5", "NTLM", "SHA1", "SHA256", "SHA512", "bcrypt", "Base64"]
        else:
            options = [hash_type]
        self.hash_type_override.set(options[0])
        self.hash_type_dropdown["menu"].delete(0, "end")
        for opt in options:
            self.hash_type_dropdown["menu"].add_command(label=opt, command=tk._setit(self.hash_type_override, opt))

    def crack_threaded(self):
        t = threading.Thread(target=self.crack)
        t.start()

    def crack(self):
        hash_value = self.hash_entry.get().strip()
        hash_type = self.hash_type_override.get().strip() or detect_hash_type(hash_value)
        salt = self.salt_entry.get().strip() if self.salt_entry.get().strip() else None
        rules = [rule.strip() for rule in self.rules_entry.get().split(',') if rule.strip()]
        if not self.wordlist_path:
            self.output("❗ Load a wordlist first.")
            return
        self.output(f"🔍 Cracking {hash_type} hash...")
        crack_hash(hash_value, self.wordlist_path, hash_type, self.output, salt, rules)

    def generate_hashes(self):
        password = self.gen_entry.get()
        if not password:
            self.gen_output.insert(tk.END, "❗ Please enter a password.\n")
            return
        try:
            hashes = generate_hashes(password)
            self.gen_output.delete(1.0, tk.END)
            self.gen_output.insert(tk.END, "🔐 Generated Hashes:\n\n")
            for algo, value in hashes.items():
                self.gen_output.insert(tk.END, f"{algo}: {value}\n\n")  # line break for clarity
        except Exception as e:
            self.gen_output.insert(tk.END, f"⚠️ Error generating hashes: {e}\n")

    def output(self, message):
        self.output_text.insert(tk.END, message + "\n")
        self.output_text.see(tk.END)

if __name__ == "__main__":
    root = tk.Tk()
    app = HashBreakerGUI(root)
    root.geometry("1000x700")
    root.minsize(800, 500)
    root.mainloop()

