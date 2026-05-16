import customtkinter as ctk
import math
from Crypto.Cipher import DES, AES

# ==========================================
# 1. Algorithms Logic (Simplified & Readable)
# ==========================================

# --- Vigenère Cipher ---
def vigenere_encrypt(plaintext, key_str):
    key_str = key_str.upper()
    result_chars = []
    key_idx = 0
    
    for char in plaintext:
        if char.isalpha():
            # 1. حساب مقدار الإزاحة بناءً على حرف المفتاح الحالي
            shift_val = ord(key_str[key_idx % len(key_str)]) - 65
            
            # 2. تحديد ما إذا كان الحرف الأصلي كبيراً أم صغيراً
            ascii_base = 65 if char.isupper() else 97
            
            # 3. تطبيق معادلة التشفير (تفكيك المعادلة لتسهيل الشرح)
            char_index = ord(char) - ascii_base       # تحويل الحرف لرقم من 0 إلى 25
            new_index = (char_index + shift_val) % 26 # إضافة الإزاحة مع أخذ باقي القسمة
            encrypted_char = chr(new_index + ascii_base) # إعادة الرقم إلى حرف
            
            result_chars.append(encrypted_char)
            key_idx += 1
        else:
            # إذا لم يكن حرفاً (مثل الأرقام والمسافات)، اتركه كما هو
            result_chars.append(char)
            
    return "".join(result_chars)

def vigenere_decrypt(ciphertext, key_str):
    key_str = key_str.upper()
    result_chars = []
    key_idx = 0
    
    for char in ciphertext:
        if char.isalpha():
            shift_val = ord(key_str[key_idx % len(key_str)]) - 65
            ascii_base = 65 if char.isupper() else 97
            
            # عملية فك التشفير (نطرح الإزاحة بدلاً من جمعها ونضيف 26 لنتجنب القيم السالبة)
            char_index = ord(char) - ascii_base
            new_index = (char_index - shift_val + 26) % 26
            decrypted_char = chr(new_index + ascii_base)
            
            result_chars.append(decrypted_char)
            key_idx += 1
        else:
            result_chars.append(char)
            
    return "".join(result_chars)

# --- Vernam Cipher ---
def vernam_encrypt(plaintext, key_str):
    if len(plaintext) != len(key_str): 
        return "ERROR: Key length must equal Plain Text length!"
    
    # --- حالة التشفير الثنائي (0 و 1) ---
    if set(plaintext).issubset({'0', '1', ' '}) and set(key_str).issubset({'0', '1', ' '}):
        pt_clean = plaintext.replace(" ", "")
        k_clean = key_str.replace(" ", "")
        result_binary = ""
        
        # حلقة بسيطة لإجراء XOR بين كل بت والنظير له
        for i in range(len(pt_clean)):
            xor_bit = int(pt_clean[i]) ^ int(k_clean[i])
            result_binary += str(xor_bit)
        return result_binary
        
    # --- حالة تشفير النصوص ---
    pt_upper = plaintext.upper()
    k_upper = key_str.upper()
    cipher_output = ""
    
    for i in range(len(pt_upper)):
        pt_char = pt_upper[i]
        k_char = k_upper[i]
        
        if pt_char.isalpha() and k_char.isalpha():
            # تحويل الأحرف إلى أرقام من 0 لـ 25 ثم عمل XOR
            xor_val = (ord(pt_char) - 65) ^ (ord(k_char) - 65)
            
            # التأكد أن النتيجة لا تتجاوز الأحرف الأبجدية
            if xor_val >= 26: 
                xor_val -= 26
                
            cipher_output += chr(xor_val + 65)
        else:
            cipher_output += pt_char
            
    return cipher_output

def vernam_decrypt(ciphertext, key_str):
    # Vernam هو متماثل (Symmetric)، فك التشفير يشبه التشفير
    # سنقوم بعكس العملية باستخدام الـ XOR
    if len(ciphertext) != len(key_str): 
        return "ERROR: Key length must match original Plain Text length!"
    
    # حالة التشفير الثنائي
    if set(ciphertext).issubset({'0', '1', ' '}) and set(key_str).issubset({'0', '1', ' '}):
        ct_clean = ciphertext.replace(" ", "")
        k_clean = key_str.replace(" ", "")
        result_binary = ""
        for i in range(len(ct_clean)):
            xor_bit = int(ct_clean[i]) ^ int(k_clean[i])
            result_binary += str(xor_bit)
        return result_binary
        
    ct_upper = ciphertext.upper()
    k_upper = key_str.upper()
    plain_output = ""
    
    for i in range(len(ct_upper)):
        ct_char = ct_upper[i]
        k_char = k_upper[i]
        
        if ct_char.isalpha() and k_char.isalpha():
            ct_val = ord(ct_char) - 65
            k_val = ord(k_char) - 65
            matched_char = "?"
            
            # نجرب كل الأحرف من 0 لـ 25 لنرى أيها يعطينا الحرف المشفر عند عمل XOR مع المفتاح
            for test_val in range(26):
                temp_xor = test_val ^ k_val
                if temp_xor >= 26: 
                    temp_xor -= 26
                    
                if temp_xor == ct_val:
                    matched_char = chr(test_val + 65)
                    break
                    
            plain_output += matched_char
        else:
            plain_output += ct_char
            
    return plain_output

# --- Playfair Cipher ---
def playfair_matrix(key_input):
    alphabet_pool = "ABCDEFGHIKLMNOPQRSTUVWXYZ"
    clean_key = ""
    
    # تنظيف المفتاح من الرموز واستبدال J بـ I
    for ch in key_input:
        if ch.isalpha():
            clean_key += ch.upper()
    clean_key = clean_key.replace("J", "I")
    
    # بناء المصفوفة بدون تكرار الأحرف
    matrix_elements = []
    for char in clean_key + alphabet_pool:
        if char not in matrix_elements:
            matrix_elements.append(char)
            
    # تقسيم الأحرف إلى 5 صفوف كل صف فيه 5 أحرف
    grid = []
    for idx in range(0, 25, 5):
        row = matrix_elements[idx : idx + 5]
        grid.append(row)
        
    return grid

def locate_in_matrix(grid, target_char):
    # البحث عن موقع الحرف (الصف والعمود) في مصفوفة 5x5
    for row_idx in range(5):
        for col_idx in range(5):
            if grid[row_idx][col_idx] == target_char:
                return row_idx, col_idx
    return -1, -1

def playfair_encrypt(plaintext, key_str):
    grid = playfair_matrix(key_str)
    
    # تنظيف النص الأصلي
    pt_clean = ""
    for ch in plaintext:
        if ch.isalpha():
            pt_clean += ch.upper()
    pt_clean = pt_clean.replace("J", "I")
    
    # إضافة حرف X إذا كان هناك حرفان متتاليان متشابهان
    idx = 0
    padded_text = ""
    while idx < len(pt_clean) - 1:
        if pt_clean[idx] == pt_clean[idx+1]: 
            padded_text += pt_clean[idx] + "X"
            idx += 1
        else:
            padded_text += pt_clean[idx] + pt_clean[idx+1]
            idx += 2
            
    # إذا كان الحرف الأخير متبقياً لوحده، نضيف له X
    if idx < len(pt_clean):
        padded_text += pt_clean[idx] + "X"
    
    # التشفير بناءً على القواعد الثلاث للمصفوفة
    encrypted_text = ""
    for i in range(0, len(padded_text), 2):
        r1, c1 = locate_in_matrix(grid, padded_text[i])
        r2, c2 = locate_in_matrix(grid, padded_text[i+1])
        
        if r1 == r2: # نفس الصف
            encrypted_text += grid[r1][(c1+1)%5] + grid[r2][(c2+1)%5]
        elif c1 == c2: # نفس العمود
            encrypted_text += grid[(r1+1)%5][c1] + grid[(r2+1)%5][c2]
        else: # شكل مستطيل
            encrypted_text += grid[r1][c2] + grid[r2][c1]
            
    return encrypted_text

# --- RC4 Cipher ---
def execute_rc4(data_array, key_array):
    # الخطوة 1: التهيئة (Initialization)
    s_box = list(range(256))
    t_array = []
    for i in range(256):
        t_array.append(key_array[i % len(key_array)])
    
    # الخطوة 2: التبديل الأولي (Initial Permutation)
    j_idx = 0
    for i in range(256):
        j_idx = (j_idx + s_box[i] + t_array[i]) % 256
        # تبديل القيم
        temp = s_box[i]
        s_box[i] = s_box[j_idx]
        s_box[j_idx] = temp
        
    # الخطوة 3: توليد المفتاح المستمر والتشفير (Stream Generation)
    i_idx = 0
    j_idx = 0
    output_stream = []
    
    for byte_val in data_array: 
        i_idx = (i_idx + 1) % 256
        j_idx = (j_idx + s_box[i_idx]) % 256
        
        # تبديل القيم
        temp = s_box[i_idx]
        s_box[i_idx] = s_box[j_idx]
        s_box[j_idx] = temp
        
        # استخراج مفتاح التشفير الحالي وعمل XOR
        t = (s_box[i_idx] + s_box[j_idx]) % 256
        stream_key = s_box[t] 
        output_stream.append(byte_val ^ stream_key)
        
    return output_stream

def rc4_encrypt(plaintext, key_str):
    try:
        # تحويل المدخلات إلى قوائم أرقام
        pt_nums = []
        for num in plaintext.replace(',', ' ').split():
            pt_nums.append(int(num))
            
        k_nums = []
        for num in key_str.replace(',', ' ').split():
            k_nums.append(int(num))
        
        processed_data = execute_rc4(pt_nums, k_nums)
        
        # تحويل الأرقام الناتجة إلى نصوص مفصولة بمسافات لطباعتها
        result_strings = []
        for val in processed_data:
            result_strings.append(str(val))
            
        return " ".join(result_strings)
    except ValueError:
        return "ERROR: RC4 requires NUMBERS ONLY separated by spaces (e.g. 10 20 30)."
    except Exception as err:
        return f"ERROR: {str(err)}"

def rc4_decrypt(ciphertext, key_str):
    return rc4_encrypt(ciphertext, key_str) # RC4 خوارزمية متماثلة

# --- RSA Cipher ---
def rsa_process(text_data, key_info):
    try:
        # استخراج المتغيرات e و n من المفتاح
        parts = key_info.split(",")
        power_val = int(parts[0])
        mod_val = int(parts[1])
        
        blocks = text_data.split()
        result_blocks = []
        
        # تطبيق المعادلة: (النص أس e) باقي قسمة n
        for block in blocks:
            number = int(block)
            encrypted_num = pow(number, power_val, mod_val)
            result_blocks.append(str(encrypted_num))
            
        return " ".join(result_blocks)
    except: 
        return "ERROR: Key must be in format 'key,n' (e.g. 17,3233)"

def rsa_decrypt(ciphertext, key_info):
    return rsa_process(ciphertext, key_info) # نفس العملية الرياضية لفك التشفير

# --- MD5 & SHA-256 ---
# ملاحظة: تم تركها كما هي لأنها تعتمد كلياً على الإزاحات البيتية (Bitwise) الثابتة عالمياً ولا يمكن تبسيطها برمجياً أكثر من ذلك.
def bit_rotate_left(val, amount):
    return ((val << amount) | (val >> (32 - amount))) & 0xFFFFFFFF

def bit_rotate_right(val, amount):
    return ((val >> amount) | (val << (32 - amount))) & 0xFFFFFFFF

def md5_custom(msg_string):
    sine_table = [int(abs(math.sin(i + 1)) * (2**32)) & 0xFFFFFFFF for i in range(64)]
    shift_amounts = [7, 12, 17, 22]*4 + [5, 9, 14, 20]*4 + [4, 11, 16, 23]*4 + [6, 10, 15, 21]*4
    reg_a, reg_b, reg_c, reg_d = 0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476
    
    raw_bytes = bytearray(msg_string.encode('utf-8'))
    bit_length = (8 * len(raw_bytes)) & 0xFFFFFFFFFFFFFFFF
    raw_bytes.append(0x80)
    while len(raw_bytes) % 64 != 56: 
        raw_bytes.append(0x00)
    raw_bytes += bit_length.to_bytes(8, byteorder='little')

    for offset in range(0, len(raw_bytes), 64):
        block = raw_bytes[offset : offset + 64]
        words = [int.from_bytes(block[4*i : 4*i+4], byteorder='little') for i in range(16)]
        a, b, c, d = reg_a, reg_b, reg_c, reg_d
        
        for i in range(64):
            if i < 16:
                func_val, g_idx = (b & c) | ((~b) & d), i
            elif i < 32:
                func_val, g_idx = (d & b) | ((~d) & c), (5 * i + 1) % 16
            elif i < 48:
                func_val, g_idx = b ^ c ^ d, (3 * i + 5) % 16
            else:
                func_val, g_idx = c ^ (b | (~d)), (7 * i) % 16
                
            func_val = (func_val + a + sine_table[i] + words[g_idx]) & 0xFFFFFFFF
            a, d, c, b = d, c, b, (b + bit_rotate_left(func_val, shift_amounts[i])) & 0xFFFFFFFF
            
        reg_a, reg_b, reg_c, reg_d = (reg_a + a) & 0xFFFFFFFF, (reg_b + b) & 0xFFFFFFFF, (reg_c + c) & 0xFFFFFFFF, (reg_d + d) & 0xFFFFFFFF
        
    return (reg_a.to_bytes(4, 'little') + reg_b.to_bytes(4, 'little') + reg_c.to_bytes(4, 'little') + reg_d.to_bytes(4, 'little')).hex()

def sha256_custom(msg_string):
    k_constants = [0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2]
    hash_vals = [0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]
    
    raw_bytes = bytearray(msg_string.encode('utf-8'))
    bit_length = (8 * len(raw_bytes)) & 0xFFFFFFFFFFFFFFFF
    raw_bytes.append(0x80)
    while len(raw_bytes) % 64 != 56: 
        raw_bytes.append(0x00)
    raw_bytes += bit_length.to_bytes(8, byteorder='big')

    for offset in range(0, len(raw_bytes), 64):
        block = raw_bytes[offset : offset + 64]
        msg_schedule = [0] * 64
        
        for i in range(16): 
            msg_schedule[i] = int.from_bytes(block[4*i : 4*i+4], byteorder='big')
            
        for i in range(16, 64):
            s0 = bit_rotate_right(msg_schedule[i-15], 7) ^ bit_rotate_right(msg_schedule[i-15], 18) ^ (msg_schedule[i-15] >> 3)
            s1 = bit_rotate_right(msg_schedule[i-2], 17) ^ bit_rotate_right(msg_schedule[i-2], 19) ^ (msg_schedule[i-2] >> 10)
            msg_schedule[i] = (msg_schedule[i-16] + s0 + msg_schedule[i-7] + s1) & 0xFFFFFFFF
            
        a, b, c, d, e, f, g, h = hash_vals
        
        for i in range(64):
            sum1 = bit_rotate_right(e, 6) ^ bit_rotate_right(e, 11) ^ bit_rotate_right(e, 25)
            ch = (e & f) ^ ((~e) & g)
            temp1 = (h + sum1 + ch + k_constants[i] + msg_schedule[i]) & 0xFFFFFFFF
            sum0 = bit_rotate_right(a, 2) ^ bit_rotate_right(a, 13) ^ bit_rotate_right(a, 22)
            maj = (a & b) ^ (a & c) ^ (b & c)
            temp2 = (sum0 + maj) & 0xFFFFFFFF
            
            h, g, f, e, d, c, b, a = g, f, e, (d + temp1) & 0xFFFFFFFF, c, b, a, (temp1 + temp2) & 0xFFFFFFFF
            
        hash_vals = [(x + y) & 0xFFFFFFFF for x, y in zip(hash_vals, [a, b, c, d, e, f, g, h])]
        
    return ''.join(f'{val:08x}' for val in hash_vals)

# --- DES  ---
def des_custom_encrypt(plaintext, key_str):
    try:
        pt_hex = plaintext.replace(" ", "").strip()
        k_hex = key_str.replace(" ", "").strip()
        
        if len(pt_hex) != 16 or len(k_hex) != 16: 
            return "ERROR: DES requires exactly 16 Hex characters."
        
        cipher_engine = DES.new(bytes.fromhex(k_hex), DES.MODE_ECB)
        encrypted_data = cipher_engine.encrypt(bytes.fromhex(pt_hex))
        
        return encrypted_data.hex().upper()
    except ValueError: 
        return "ERROR: Invalid input! Use Hex characters only (0-9, A-F)."
    except Exception as err: 
        return f"ERROR: {str(err)}"

def des_custom_decrypt(ciphertext, key_str):
    try:
        ct_hex = ciphertext.replace(" ", "").strip()
        k_hex = key_str.replace(" ", "").strip()
        
        if len(ct_hex) != 16 or len(k_hex) != 16: 
            return "ERROR: DES requires exactly 16 Hex characters."
        
        cipher_engine = DES.new(bytes.fromhex(k_hex), DES.MODE_ECB)
        decrypted_data = cipher_engine.decrypt(bytes.fromhex(ct_hex))
        
        return decrypted_data.hex().upper()
    except ValueError: 
        return "ERROR: Invalid input! Use Hex characters only (0-9, A-F)."
    except Exception as err: 
        return f"ERROR: {str(err)}"

# --- AES ---
def aes_custom_encrypt(plaintext, key_str):
    try:
        pt_hex = plaintext.replace(" ", "").strip()
        k_hex = key_str.replace(" ", "").strip()
        
        if len(pt_hex) != 32 or len(k_hex) != 32: 
            return "ERROR: AES requires exactly 32 Hex characters."
        
        cipher_engine = AES.new(bytes.fromhex(k_hex), AES.MODE_ECB)
        encrypted_data = cipher_engine.encrypt(bytes.fromhex(pt_hex))
        
        return encrypted_data.hex().upper()
    except ValueError: 
        return "ERROR: Invalid input! Use Hex characters only (0-9, A-F)."
    except Exception as err: 
        return f"ERROR: {str(err)}"

def aes_custom_decrypt(ciphertext, key_str):
    try:
        ct_hex = ciphertext.replace(" ", "").strip()
        k_hex = key_str.replace(" ", "").strip()
        
        if len(ct_hex) != 32 or len(k_hex) != 32: 
            return "ERROR: AES requires exactly 32 Hex characters."
        
        cipher_engine = AES.new(bytes.fromhex(k_hex), AES.MODE_ECB)
        decrypted_data = cipher_engine.decrypt(bytes.fromhex(ct_hex))
        
        return decrypted_data.hex().upper()
    except ValueError: 
        return "ERROR: Invalid input! Use Hex characters only (0-9, A-F)."
    except Exception as err: 
        return f"ERROR: {str(err)}"


# ==========================================
# 2. GUI 
# ==========================================

ctk.set_appearance_mode("Dark")  
BG_MAIN = "#0D1117"        
BG_SIDEBAR = "#161B22"     
ACCENT = "#00FF66"         
ACCENT_HOVER = "#00CC52"   
TEXT_PRIMARY = "#FFFFFF"   
TEXT_MUTED = "#8B949E"     
INPUT_BG = "#010409"       
BORDER = "#30363D"         

class CryptoApp(ctk.CTk):
    def __init__(self):
        super().__init__()
        self.title("Advanced Encryption Tool | Pro Version")
        self.geometry("950x650")
        self.configure(fg_color=BG_MAIN)
        
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        self.sidebar = ctk.CTkFrame(self, fg_color=BG_SIDEBAR, corner_radius=0, border_width=1, border_color=BORDER)
        self.sidebar.grid(row=0, column=0, sticky="nsew")
        self.sidebar.grid_rowconfigure(5, weight=1)

        title_lbl = ctk.CTkLabel(self.sidebar, text="SECURE", font=("Impact", 35), text_color=TEXT_PRIMARY)
        title_lbl.grid(row=0, column=0, padx=20, pady=(25, 0), sticky="w")
        sub_lbl = ctk.CTkLabel(self.sidebar, text="CRYPTO ENGINE", font=("Impact", 25), text_color=ACCENT)
        sub_lbl.grid(row=1, column=0, padx=20, pady=(0, 25), sticky="w")

        ctk.CTkLabel(self.sidebar, text="SELECT ALGORITHM:", font=("Arial", 12, "bold"), text_color=TEXT_MUTED).grid(row=2, column=0, padx=20, pady=(10, 5), sticky="w")
        algos = ["Vigenère Cipher", "Vernam Cipher", "Playfair", "DES", "AES", "RC4", "RSA", "Hashing (MD5/SHA)"]
        self.algo_var = ctk.StringVar(value=algos[0])
        self.algo_menu = ctk.CTkOptionMenu(self.sidebar, variable=self.algo_var, values=algos, fg_color=INPUT_BG, button_color=ACCENT, button_hover_color=ACCENT_HOVER, text_color=TEXT_PRIMARY, font=("Consolas", 14), height=40)
        self.algo_menu.grid(row=3, column=0, padx=20, pady=(0, 20), sticky="ew")

        ctk.CTkLabel(self.sidebar, text="ENCRYPTION KEY:", font=("Arial", 12, "bold"), text_color=TEXT_MUTED).grid(row=4, column=0, padx=20, pady=(10, 5), sticky="w")
        self.key_entry = ctk.CTkEntry(self.sidebar, placeholder_text="Enter key here...", font=("Consolas", 14), fg_color=INPUT_BG, border_color=BORDER, text_color=TEXT_PRIMARY, height=45)
        self.key_entry.grid(row=5, column=0, padx=20, pady=(0, 20), sticky="nw")

        self.btn_enc = ctk.CTkButton(self.sidebar, text="[ ENCRYPT ]", font=("Consolas", 16, "bold"), fg_color=ACCENT, text_color=INPUT_BG, hover_color=ACCENT_HOVER, height=50, command=self.encrypt)
        self.btn_enc.grid(row=6, column=0, padx=20, pady=10, sticky="ew")
        
        self.btn_dec = ctk.CTkButton(self.sidebar, text="[ DECRYPT ]", font=("Consolas", 16, "bold"), fg_color="transparent", border_width=2, border_color=ACCENT, text_color=ACCENT, hover_color=BG_MAIN, height=50, command=self.decrypt)
        self.btn_dec.grid(row=7, column=0, padx=20, pady=10, sticky="ew")

        self.btn_clear = ctk.CTkButton(self.sidebar, text="CLEAR DATA", font=("Arial", 12, "bold"), fg_color=BORDER, text_color=TEXT_PRIMARY, hover_color="#4b5563", height=40, command=self.clear)
        self.btn_clear.grid(row=8, column=0, padx=20, pady=(10, 25), sticky="ew")

        self.main_panel = ctk.CTkFrame(self, fg_color=BG_MAIN, corner_radius=0)
        self.main_panel.grid(row=0, column=1, sticky="nsew", padx=25, pady=25)
        self.main_panel.grid_columnconfigure(0, weight=1)
        self.main_panel.grid_rowconfigure((1, 3), weight=1)

        ctk.CTkLabel(self.main_panel, text=">> INPUT TEXT", font=("Consolas", 16, "bold"), text_color=ACCENT).grid(row=0, column=0, sticky="w", pady=(0, 5))
        self.input_text = ctk.CTkTextbox(self.main_panel, font=("Consolas", 15), fg_color=INPUT_BG, text_color=TEXT_PRIMARY, border_color=BORDER, border_width=2)
        self.input_text.grid(row=1, column=0, sticky="nsew", pady=(0, 20))

        ctk.CTkLabel(self.main_panel, text=">> OUTPUT RESULT", font=("Consolas", 16, "bold"), text_color=ACCENT).grid(row=2, column=0, sticky="w", pady=(0, 5))
        self.output_text = ctk.CTkTextbox(self.main_panel, font=("Consolas", 15), fg_color=INPUT_BG, text_color=ACCENT, border_color=BORDER, border_width=2)
        self.output_text.grid(row=3, column=0, sticky="nsew")

    def display(self, text):
        self.output_text.delete("0.0", "end")
        self.output_text.insert("0.0", text)

    def encrypt(self):
        p = self.input_text.get("0.0", "end").strip()
        k = self.key_entry.get().strip()
        a = self.algo_var.get()
        if not p: return self.display("ERROR: Plain Text is empty!")

        try:
            if a == "Vigenère Cipher": res = vigenere_encrypt(p, k) if k else "ERROR: Key required."
            elif a == "Vernam Cipher": res = vernam_encrypt(p, k) if k else "ERROR: Key required."
            elif a == "Playfair": res = playfair_encrypt(p, k) if k else "ERROR: Key required."
            elif a == "RC4": res = rc4_encrypt(p, k) if k else "ERROR: Key required."
            elif a == "RSA": res = rsa_process(p, k) if k else "ERROR: Key required (e.g. 17,3233)."
            elif a == "DES": res = des_custom_encrypt(p, k)
            elif a == "AES": res = aes_custom_encrypt(p, k)
            elif a == "Hashing (MD5/SHA)":
                res = f"[ MD5 HASH ]\n{md5_custom(p)}\n\n[ SHA-256 HASH ]\n{sha256_custom(p)}"
            self.display(res)
        except Exception as e: self.display(f"SYSTEM ERROR: {str(e)}")

    def decrypt(self):
        c = self.input_text.get("0.0", "end").strip()
        k = self.key_entry.get().strip()
        a = self.algo_var.get()
        if not c: return self.display("ERROR: Cipher Text is empty!")
        if a == "Hashing (MD5/SHA)": return self.display("ERROR: Hashing is one-way, cannot be decrypted!")

        try:
            if a == "Vigenère Cipher": res = vigenere_decrypt(c, k) if k else "ERROR: Key required."
            elif a == "Vernam Cipher": res = vernam_decrypt(c, k) if k else "ERROR: Key required."
            elif a == "Playfair": res = "ERROR: Playfair decryption not standard, text is lossy (X added)."
            elif a == "RC4": res = rc4_decrypt(c, k) if k else "ERROR: Key required."
            elif a == "RSA": res = rsa_decrypt(c, k) if k else "ERROR: Key required (e.g. 2753,3233)."
            elif a == "DES": res = des_custom_decrypt(c, k)
            elif a == "AES": res = aes_custom_decrypt(c, k)
            self.display(res)
        except Exception as e: self.display(f"DECRYPTION ERROR: Check key validity or format. ({str(e)})")

    def clear(self):
        self.input_text.delete("0.0", "end")
        self.key_entry.delete(0, "end")
        self.output_text.delete("0.0", "end")

if __name__ == "__main__":
    app = CryptoApp()
    app.mainloop()