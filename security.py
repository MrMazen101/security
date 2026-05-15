import tkinter as tk
from tkinter import ttk, messagebox
from Crypto.Cipher import AES, DES
from Crypto.Util.Padding import pad, unpad

class SecurityApp:
    def __init__(self, root):
        self.root = root
        self.root.title("Advanced Security Project 2026")
        self.root.geometry("700x550")
        self.root.configure(bg="#2b2b2b")
        
        # RSA Global Variables (From Scratch)
        self.rsa_keys_generated = False
        self.rsa_e = 0
        self.rsa_d = 0
        self.rsa_n = 0

        self.setup_ui()

    def setup_ui(self):
        style = ttk.Style()
        style.theme_use('clam')
        style.configure("TLabel", background="#2b2b2b", foreground="white", font=("Arial", 11, "bold"))
        style.configure("TButton", font=("Arial", 10, "bold"), padding=5)

        # Plain Text
        ttk.Label(self.root, text="Plain Text:").place(x=30, y=20)
        self.txt_plain = tk.Text(self.root, height=7, width=35, font=("Consolas", 10))
        self.txt_plain.place(x=30, y=50)

        # Cipher Text
        ttk.Label(self.root, text="Cipher Text:").place(x=390, y=20)
        self.txt_cipher = tk.Text(self.root, height=7, width=35, font=("Consolas", 10))
        self.txt_cipher.place(x=390, y=50)

        # Key
        ttk.Label(self.root, text="Key:").place(x=150, y=200)
        self.ent_key = ttk.Entry(self.root, width=40, font=("Consolas", 11))
        self.ent_key.place(x=150, y=230)

        # Algorithm Selection
        ttk.Label(self.root, text="Algorithm:").place(x=250, y=280)
        self.algo_var = tk.StringVar()
        self.cmb_algo = ttk.Combobox(self.root, textvariable=self.algo_var, state="readonly", width=30)
        self.cmb_algo['values'] = ("Vigenère Cipher", "Vernam Cipher", "Playfair", "AES", "DES", "RC4", "Hashing (Custom SHA-like)", "RSA")
        self.cmb_algo.current(0)
        self.cmb_algo.place(x=250, y=310)

        # Buttons
        btn_encrypt = tk.Button(self.root, text="ENCRYPT", bg="#28a745", fg="white", font=("Arial", 12, "bold"), command=self.encrypt_action)
        btn_encrypt.place(x=180, y=400, width=100, height=40)

        btn_clear = tk.Button(self.root, text="CLEAR", bg="#ffc107", fg="black", font=("Arial", 12, "bold"), command=self.clear_action)
        btn_clear.place(x=300, y=400, width=100, height=40)

        btn_decrypt = tk.Button(self.root, text="DECRYPT", bg="#dc3545", fg="white", font=("Arial", 12, "bold"), command=self.decrypt_action)
        btn_decrypt.place(x=420, y=400, width=100, height=40)

    # ================== Button Actions ==================
    def clear_action(self):
        self.txt_plain.delete("1.0", tk.END)
        self.txt_cipher.delete("1.0", tk.END)
        self.ent_key.delete(0, tk.END)

    def encrypt_action(self):
        plain = self.txt_plain.get("1.0", "end-1c")
        key = self.ent_key.get()
        algo = self.algo_var.get()

        if not key and algo not in ["Hashing (Custom SHA-like)", "RSA"]:
            messagebox.showwarning("Missing Key", "Please enter a key!")
            return

        try:
            res = ""
            if algo == "Vigenère Cipher": res = self.vigenere_encrypt(plain, key)
            elif algo == "Vernam Cipher":
                if len(plain) != len(key):
                    messagebox.showwarning("Error", "Vernam needs Key length == Text length!")
                    return
                res = self.vernam_encrypt(plain, key)
            elif algo == "Playfair": res = self.playfair_encrypt(plain, key)
            elif algo == "AES": res = self.aes_encrypt(plain, key)
            elif algo == "DES": res = self.des_encrypt(plain, key)
            elif algo == "RC4": res = self.rc4_crypt(plain, key, encrypt=True)
            elif algo == "Hashing (Custom SHA-like)": res = self.custom_hash(plain)
            elif algo == "RSA": res = self.rsa_encrypt(plain)
            
            self.txt_cipher.delete("1.0", tk.END)
            self.txt_cipher.insert(tk.END, res)
        except Exception as e:
            messagebox.showerror("Error", str(e))

    def decrypt_action(self):
        cipher = self.txt_cipher.get("1.0", "end-1c").replace("\n", "").replace(" ", "")
        key = self.ent_key.get()
        algo = self.algo_var.get()

        if not key and algo not in ["Hashing (Custom SHA-like)", "RSA"]:
            messagebox.showwarning("Missing Key", "Please enter a key!")
            return

        if algo == "Hashing (Custom SHA-like)":
            messagebox.showwarning("Hashing Error", "Hashing is one-way. CANNOT be decrypted!")
            return

        try:
            res = ""
            if algo == "Vigenère Cipher": res = self.vigenere_decrypt(cipher, key)
            elif algo == "Vernam Cipher": res = self.vernam_decrypt(cipher, key)
            elif algo == "Playfair": res = self.playfair_decrypt(cipher, key)
            elif algo == "AES": res = self.aes_decrypt(cipher, key)
            elif algo == "DES": res = self.des_decrypt(cipher, key)
            elif algo == "RC4": res = self.rc4_crypt(cipher, key, encrypt=False)
            elif algo == "RSA": 
                cipher_with_spaces = self.txt_cipher.get("1.0", "end-1c") # RSA needs spaces
                res = self.rsa_decrypt(cipher_with_spaces)
            
            self.txt_plain.delete("1.0", tk.END)
            self.txt_plain.insert(tk.END, res)
        except Exception as e:
            messagebox.showerror("Decryption Error", "Invalid Key or Corrupted Data!")

    # ================== 1. Vigenère (From Scratch) ==================
    def vigenere_encrypt(self, text, key):
        res, j, key = "", 0, key.upper()
        for c in text:
            if c.isalpha():
                shift = ord(key[j % len(key)]) - 65
                base = 65 if c.isupper() else 97
                res += chr((ord(c) - base + shift) % 26 + base)
                j += 1
            else: res += c
        return res

    def vigenere_decrypt(self, text, key):
        res, j, key = "", 0, key.upper()
        for c in text:
            if c.isalpha():
                shift = ord(key[j % len(key)]) - 65
                base = 65 if c.isupper() else 97
                res += chr((ord(c) - base - shift + 26) % 26 + base)
                j += 1
            else: res += c
        return res

    # ================== 2. Vernam (From Scratch) ==================
    def vernam_encrypt(self, text, key):
        res, text, key = "", text.upper(), key.upper()
        for i in range(len(text)):
            if text[i].isalpha():
                res += chr(((ord(text[i]) - 65) + (ord(key[i]) - 65)) % 26 + 65)
            else: res += text[i]
        return res

    def vernam_decrypt(self, text, key):
        res, text, key = "", text.upper(), key.upper()
        for i in range(len(text)):
            if text[i].isalpha():
                res += chr(((ord(text[i]) - 65) - (ord(key[i]) - 65) + 26) % 26 + 65)
            else: res += text[i]
        return res

    # ================== 3. Playfair (From Scratch) ==================
    def build_playfair_matrix(self, key):
        matrix, used = "", set(['J'])
        for char in key.upper():
            if char.isalpha() and char not in used:
                matrix += char
                used.add(char)
        for char in "ABCDEFGHIKLMNOPQRSTUVWXYZ":
            if char not in used:
                matrix += char
                used.add(char)
        return matrix

    def playfair_encrypt(self, text, key):
        matrix = self.build_playfair_matrix(key)
        text = [c.upper() if c.upper() != 'J' else 'I' for c in text if c.isalpha()]
        i = 0
        while i < len(text) - 1:
            if text[i] == text[i+1]: text.insert(i+1, 'X')
            i += 2
        if len(text) % 2 != 0: text.append('X')
        
        res = ""
        for i in range(0, len(text), 2):
            p1, p2 = matrix.index(text[i]), matrix.index(text[i+1])
            r1, c1, r2, c2 = p1//5, p1%5, p2//5, p2%5
            if r1 == r2: res += matrix[r1*5 + (c1+1)%5] + matrix[r2*5 + (c2+1)%5]
            elif c1 == c2: res += matrix[((r1+1)%5)*5 + c1] + matrix[((r2+1)%5)*5 + c2]
            else: res += matrix[r1*5 + c2] + matrix[r2*5 + c1]
        return res

    def playfair_decrypt(self, text, key):
        matrix = self.build_playfair_matrix(key)
        res = ""
        for i in range(0, len(text), 2):
            p1, p2 = matrix.index(text[i]), matrix.index(text[i+1])
            r1, c1, r2, c2 = p1//5, p1%5, p2//5, p2%5
            if r1 == r2: res += matrix[r1*5 + (c1-1)%5] + matrix[r2*5 + (c2-1)%5]
            elif c1 == c2: res += matrix[((r1-1)%5)*5 + c1] + matrix[((r2-1)%5)*5 + c2]
            else: res += matrix[r1*5 + c2] + matrix[r2*5 + c1]
        return res

    # ================== 4. AES (Built-in pycryptodome) ==================
    def aes_encrypt(self, text, key):
        k = (key.encode() * 16)[:16] # Adjust to 16 bytes
        cipher = AES.new(k, AES.MODE_ECB)
        return cipher.encrypt(pad(text.encode(), AES.block_size)).hex().upper()

    def aes_decrypt(self, text, key):
        k = (key.encode() * 16)[:16]
        cipher = AES.new(k, AES.MODE_ECB)
        return unpad(cipher.decrypt(bytes.fromhex(text)), AES.block_size).decode()

    # ================== 5. DES (Built-in pycryptodome) ==================
    def des_encrypt(self, text, key):
        k = (key.encode() * 8)[:8] # Adjust to 8 bytes
        cipher = DES.new(k, DES.MODE_ECB)
        return cipher.encrypt(pad(text.encode(), DES.block_size)).hex().upper()

    def des_decrypt(self, text, key):
        k = (key.encode() * 8)[:8]
        cipher = DES.new(k, DES.MODE_ECB)
        return unpad(cipher.decrypt(bytes.fromhex(text)), DES.block_size).decode()

    # ================== 6. RC4 (From Scratch) ==================
    def rc4_crypt(self, text, key, encrypt=True):
        S = list(range(256))
        j = 0
        k_bytes = [ord(c) for c in (key if key else "0")]
        
        for i in range(256):
            j = (j + S[i] + k_bytes[i % len(k_bytes)]) % 256
            S[i], S[j] = S[j], S[i]

        i, j, res = 0, 0, []
        data = text.encode() if encrypt else bytes.fromhex(text)
        
        for byte in data:
            i = (i + 1) % 256
            j = (j + S[i]) % 256
            S[i], S[j] = S[j], S[i]
            res.append(byte ^ S[(S[i] + S[j]) % 256])
            
        return bytes(res).hex().upper() if encrypt else bytes(res).decode(errors='ignore')

    # ================== 7. Hashing (From Scratch) ==================
    def custom_hash(self, text):
        h1, h2 = 5381, 0x811c9dc5
        for char in text:
            h1 = ((h1 << 5) + h1) ^ ord(char)
            h2 = (h2 ^ ord(char)) * 0x01000193
        
        # 64-character hex signature
        return f"{h1:016x}{h2:016x}{h1^h2:016x}{h1+h2:016x}".upper()

    # ================== 8. RSA (From Scratch Math) ==================
    def gcd(self, a, b):
        while b: a, b = b, a % b
        return a

    def rsa_encrypt(self, text):
        if not self.rsa_keys_generated:
            p, q = 61, 53
            self.rsa_n = p * q
            phi = (p - 1) * (q - 1)
            self.rsa_e = 3
            while self.gcd(self.rsa_e, phi) != 1: self.rsa_e += 2
            self.rsa_d = pow(self.rsa_e, -1, phi) # Built-in modular inverse
            self.rsa_keys_generated = True

        cipher = " ".join([str(pow(ord(c), self.rsa_e, self.rsa_n)) for c in text])
        return cipher

    def rsa_decrypt(self, text):
        if not self.rsa_keys_generated: return "Error: No keys. Encrypt first!"
        return "".join([chr(pow(int(c), self.rsa_d, self.rsa_n)) for c in text.split()])

if __name__ == "__main__":
    root = tk.Tk()
    app = SecurityApp(root)
    root.mainloop()