import json
import time
import sys
import os
import random
from smartcard.System import readers
from smartcard.Exceptions import NoCardException
from Crypto.Cipher import AES

# --- CONSTANTS & MAPPINGS ---
DB_FILE = 'db/material_database.json'
COLOR_DB_FILE = 'db/material_color.json'
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])
AES_KEY_CIPHER = bytes([0x48, 0x40, 0x43, 0x46, 0x6B, 0x52, 0x6E, 0x7A, 0x40, 0x4B, 0x41, 0x74, 0x42, 0x4A, 0x70, 0x32])
# Keys to try for authentication (Default and the Creality 00s)
KEYS_TO_TRY = [[0xFF]*6, [0x00]*6]

def load_color_db():
    if not os.path.exists(COLOR_DB_FILE):
        return {"0000000": "Black", "0FFFFFF": "White"}
    try:
        with open(COLOR_DB_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return {"0" + c['hex'].upper(): c['name'] for c in data.get('colors', [])}
    except:
        return {"0000000": "Black"}

WEIGHTS = [("0330", "1.0 kg"), ("0165", "0.5 kg"), ("0082", "0.25 kg")]

def load_db():
    if not os.path.exists(DB_FILE):
        print(f"[-] Error: {DB_FILE} not found.")
        sys.exit(1)
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            inner = data.get('result', data)
            items = inner.get('list', []) if isinstance(inner, dict) else inner
            return sorted([(e['base']['id'], e['base']['name']) for e in items if 'base' in e], key=lambda x: x[1])
    except:
        sys.exit(1)

def get_choice(title, items, is_weight=False):
    print(f"\n--- {title.upper()} ---")
    for i, (code, name) in enumerate(items, 1):
        display = f"{name} (Code: {code})" if is_weight else f"{name:<20}"
        print(f" {i:2}) {display}", end="\t" if i % 2 != 0 else "\n")
    while True:
        val = input(f"\nSelect {title} (1-{len(items)}): ").strip()
        try: return items[int(val)-1]
        except: print("Invalid choice.")

def generate_key_b(uid_hex):
    # UID opschonen en herhalen tot exact 16 bytes (32 chars)
    uid_raw = bytes.fromhex(uid_hex.replace(" ", ""))
    uid_16 = (uid_raw * 4)[:16] 
    
    cipher = AES.new(AES_KEY_GEN, AES.MODE_ECB)
    # De eerste 6 bytes van de encryptie is je Key B
    return list(cipher.encrypt(uid_16)[:6])

def encrypt_payload(data_str):
    cipher = AES.new(AES_KEY_CIPHER, AES.MODE_ECB)
    enc = cipher.encrypt(data_str.encode('ascii'))
    return [enc[0:16], enc[16:32], enc[32:48]]

def write_tag(conn, blocks, label):
    print(f"\n>>> [STEP] Place {label} on reader...")
    while True:
        try:
            conn.connect()
            uid_raw, _, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            uid_hex = "".join([f"{x:02X}" for x in uid_raw])
            
            # Auth fallback: try FFs then 00s
            auth_success = False
            for key in KEYS_TO_TRY:
                conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key)
                _, sw1, _ = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x60, 0x00])
                if sw1 == 0x90:
                    auth_success = True; break
            
            if not auth_success:
                print("[-] Auth Failed. Tag might be locked.")
                return False

            print(f"[*] Writing to {uid_hex}...")
            for i, data in enumerate(blocks):
                conn.transmit([0xFF, 0xD6, 0x00, 4 + i, 0x10] + list(data))
            
            key_b = generate_key_b(uid_hex)
            # Match original spool: Key A is 00s, Access Bits are FF 07 80
            trailer = [0x00] * 6 + [0xFF, 0x07, 0x80, 0x69] + key_b
            for i, data in enumerate(blocks):
                conn.transmit([0xFF, 0xD6, 0x00, 4 + i, 0x10] + list(data))

            conn.transmit([0xFF, 0xD6, 0x00, 0x07, 0x10] + trailer)
            
            print(f"✅ {label} Complete.")
            print(">>> PLEASE REMOVE TAG.")
            # Wait for tag removal
            while True:
                try: 
                    time.sleep(0.5)
                    conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                except: break
            return True
        except NoCardException: 
            time.sleep(0.5)

def main():
    print("==========================================")
    print("   OpenCFS PRO: TWIN Spool Provisioner    ")
    print("==========================================")
    
    # 1. SETUP (Only run once for the whole spool)
    mats = load_db()
    colors = sorted(list(load_color_db().items()), key=lambda x: x[1])
    
    mat_id, mat_name = get_choice("Material", mats)
    col_hex, col_name = get_choice("Color", colors)
    wgt_hex, wgt_name = get_choice("Weight", WEIGHTS, is_weight=True)
    
    # 2. GENERATE TWIN DATA (Locked-in for both tags)
    serial_no = f"{random.randint(1, 999999):06d}"
    date_code = time.strftime("%y%m%d")[1:] 
    profile = f"1A5{date_code}1B3D{mat_id}{col_hex}{wgt_hex}{serial_no}" + ("0" * 14)
    blocks = encrypt_payload(profile)

    print(f"\n[*] TWIN PROFILE READY")
    print(f"[*] Spool Serial: {serial_no}")
    print(f"[*] Material:     {mat_name}")
    print(f"[*] Color:        {col_name}")
    
    # 3. RUN BATCH WRITE
    r = readers()
    if not r: 
        print("[-] No reader detected.")
        return
    conn = r[0].createConnection()

    if write_tag(conn, blocks, "TWIN TAG #1"):
        if write_tag(conn, blocks, "TWIN TAG #2"):
            print(f"\n🎉 SUCCESS! Twin Spool {serial_no} is ready.")
            print("[!] Ensure tags are placed at the same rotation on both sides.")

if __name__ == "__main__":
    try: 
        main()
    except KeyboardInterrupt: 
        print("\nAborted.")
