import time
import sys
import json
import os
from smartcard.System import readers
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException, NoCardException, CardConnectionException
from Crypto.Cipher import AES

# --- CONFIG & KEYS (Synced with PDF) ---
DB_FILE = 'db/material_database.json'
COLOR_DB_FILE = 'db/material_color.json'
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])
AES_KEY_CIPHER = bytes([0x48, 0x40, 0x43, 0x46, 0x6B, 0x52, 0x6E, 0x7A, 0x40, 0x4B, 0x41, 0x74, 0x42, 0x4A, 0x70, 0x32])

def load_color_db():
    if not os.path.exists(COLOR_DB_FILE):
        print("[!] Color DB not found, using fallbacks.")
        return [("0000000", "Black"), ("0FFFFFF", "White")]
    try:
        with open(COLOR_DB_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            # Create a dictionary: { "0RRGGBB": "Name" }
            return {"0" + c['hex'].upper(): c['name'] for c in data.get('colors', [])}

            # MG : debug
            # Creality uses '0' + RRGGBB (7 chars total)
            #return [("0" + c['hex'].upper(), c['name']) for c in data.get('colors', [])]

    except Exception as e:
        print(f"[-] Color JSON Error: {e}")
        return [("0000000", "Black")]

# --- DYNAMIC DATABASE LOADING ---
def load_material_db():
    if not os.path.exists(DB_FILE):
        return {}
    try:
        with open(DB_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            if isinstance(data, dict):
                inner = data.get('result', data)
                items = inner.get('list', []) if isinstance(inner, dict) else []
            else:
                items = data if isinstance(data, list) else []

            mapping = {}
            for entry in items:
                if not isinstance(entry, dict): continue
                base = entry.get('base', {})
                m_id = base.get('id')
                m_name = base.get('name')
                if m_id and m_name:
                    mapping[m_id] = m_name
            return mapping
    except Exception:
        return {}

MATERIAL_MAP = load_material_db()
COLOR_MAP = load_color_db()

# --- HELPERS ---
def generate_key_b(uid_hex):
    """Calculates the unique Creality Key B for the specific Tag UID."""
    uid_data = bytes.fromhex((uid_hex * 4)[:32])
    cipher = AES.new(AES_KEY_GEN, AES.MODE_ECB)
    return list(cipher.encrypt(uid_data)[:6])

def parse_and_print(payload, trailer):
    """Decrypts the 48-char profile and prints formatted spool data."""
    cipher = AES.new(AES_KEY_CIPHER, AES.MODE_ECB)
    try:
        ascii_data = cipher.decrypt(payload).decode('ascii', errors='ignore')
        
        # Offsets from PDF Page 3
        mat_code = ascii_data[12:17]
        col_code = ascii_data[17:24]
        weight_code = ascii_data[24:28]
        serial = ascii_data[28:34]
        
        weight_str = "1.0kg" if weight_code == "0330" else "0.5kg" if weight_code == "0165" else f"Custom ({weight_code})"
        is_locked = "LOCKED (Read-Only)" if trailer[7:9] == b'\x07\x88' else "UNLOCKED (Writable)"
        
        print("\n" + "═"*45)
        print(f" 📦 MATERIAL: {MATERIAL_MAP.get(mat_code, f'Unknown ({mat_code})')}")
        print(f" 🎨 COLOR:    {COLOR_MAP.get(col_code, f'#{col_code[1:]}')}")
        print(f" ⚖️  WEIGHT:   {weight_str}")
        print(f" 🔢 SERIAL:   {serial}")
        print(f" 🔒 STATUS:   {is_locked}")
        print("═"*45)
    except Exception as e:
        print(f"[!] Decryption Error: {e}")

# --- MAIN LOOP ---
def run_reader():
    cardrequest = CardRequest(timeout=0.1, cardType=AnyCardType())
    print(f"[*] Loaded {len(MATERIAL_MAP)} material definitions.")
    print(">>> OpenCFS Reader Ready. Waiting for Spool...")
    print(">>> Press Ctrl+C to exit.\n")

    try:
        while True:
            try:
                cardservice = cardrequest.waitforcard()
                if cardservice is None: continue

                cardservice.connection.connect()
                
                # 1. Get UID & Auth
                uid_res, _, _ = cardservice.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                uid_hex = "".join([f"{x:02X}" for x in uid_res])
                
                cfs_key = generate_key_b(uid_hex)
                cardservice.connection.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + cfs_key)
                
                # Auth Block 4 with Key B (0x61)
                _, sw1, _ = cardservice.connection.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00])

                if sw1 == 0x90:
                    # 2. Read Blocks 4, 5, 6
                    full_data = b""
                    for b in [4, 5, 6]:
                        d, _, _ = cardservice.connection.transmit([0xFF, 0xB0, 0x00, b, 0x10])
                        full_data += bytes(d)
                    
                    # 3. Read Trailer for Lock Status
                    trailer, _, _ = cardservice.connection.transmit([0xFF, 0xB0, 0x00, 0x07, 0x10])
                    parse_and_print(full_data, bytes(trailer))
                    print("\n[!] Spool detected. Remove tag to scan next...")
                    
                    # 4. Wait for removal (Looping transmit until it fails)
                    while True:
                        time.sleep(0.5)
                        cardservice.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                else:
                    print(f"[!] Tag {uid_hex}: Access Denied (Wrong Key B).")
                    time.sleep(1)

            except (NoCardException, CardRequestTimeoutException, CardConnectionException):
                continue 

    except KeyboardInterrupt:
        print("\n\n[!] Closing OpenCFS Reader. Bye!")
        sys.exit(0)

if __name__ == "__main__":
    run_reader()
