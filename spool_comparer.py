import time, sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import AES

# --- CONSTANTS ---
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])
KEYS_TO_TRY = [[0xFF]*6, [0x00]*6]

def generate_key_b(uid_hex):
    uid_data = bytes.fromhex((uid_hex * 4)[:32])
    return list(AES.new(AES_KEY_GEN, AES.MODE_ECB).encrypt(uid_data)[:6])

def scan_tag(label):
    print(f"\n>>> [STEP] Place {label} on reader...")
    r = readers()
    if not r: return None
    conn = r[0].createConnection()
    
    while True:
        try:
            conn.connect()
            # 1. Get UID
            uid_raw, _, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            uid_hex = "".join([f"{x:02X}" for x in uid_raw])
            key_b = generate_key_b(uid_hex)
            
            # 2. Try Auth with Key A variants
            auth_success = False
            for key_a in KEYS_TO_TRY:
                conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key_a)
                _, sw1, _ = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x60, 0x00])
                if sw1 == 0x90:
                    auth_success = True; break
            
            if not auth_success:
                # Fallback to Auth with Key B
                conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key_b)
                _, sw1, _ = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00])
                if sw1 != 0x90:
                    print("[-] Auth Failed."); return None

            # 3. Read Blocks 4-7
            blocks = []
            for b in [4, 5, 6, 7]:
                data, _, _ = conn.transmit([0xFF, 0xB0, 0x00, b, 0x10])
                blocks.append(toHexString(data))
            
            print(f"[*] {label} Captured!")
            # Wait for tag removal
            while True:
                try: 
                    time.sleep(0.2)
                    conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                except: break
            return {"uid": uid_hex, "data": blocks}
        except Exception: time.sleep(0.5)

def main():
    print("=== OpenCFS Spool Comparison Tool ===")
    tags = {}
    order = ["ORIGINAL Side 1", "ORIGINAL Side 2", "OWN Spool Side 1", "OWN Spool Side 2"]
    
    for label in order:
        res = scan_tag(label)
        if not res: sys.exit(1)
        tags[label] = res

    print("\n" + "="*80)
    print(f"{'BLOCK':<10} | {'ORIG S1':<20} | {'OWN S1':<20} | {'MATCH?'}")
    print("-" * 80)
    
    for i in range(4):
        label = f"Block {i+4}"
        val_orig = tags["ORIGINAL Side 1"]["data"][i]
        val_own = tags["OWN Spool Side 1"]["data"][i]
        match = "YES" if val_orig == val_own else "!!! DIFF !!!"
        # Skip match check for Block 7 (Trailer) as it's UID-dependent
        if i == 3: match = "UID Dependent"
        print(f"{label:<10} | {val_orig[:20]:<20} | {val_own[:20]:<20} | {match}")

    print("\n[!] Check Block 7 (Trailer) middle 4 bytes (Access Bits) specifically.")
    print(f"ORIG S1 Trailer: {tags['ORIGINAL Side 1']['data'][3]}")
    print(f"OWN  S1 Trailer: {tags['OWN Spool Side 1']['data'][3]}")

if __name__ == "__main__":
    main()
