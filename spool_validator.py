import time, sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import AES

# --- CONFIG ---
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])

def generate_key_b(uid_hex):
    """Calculates the unique Key B for the tag's hardware ID."""
    uid_data = bytes.fromhex((uid_hex * 4)[:32])
    cipher = AES.new(AES_KEY_GEN, AES.MODE_ECB)
    return list(cipher.encrypt(uid_data)[:6])

def scan_one_tag(label):
    print(f"\n>>> [STEP] Place {label} on reader...")
    r = readers()
    if not r: 
        print("[-] No reader found."); return None
    conn = r[0].createConnection()
    
    while True:
        try:
            conn.connect()
            # 1. Get UID to calculate Key B
            uid_raw, _, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            uid_hex = "".join([f"{x:02X}" for x in uid_raw])
            key_b = generate_key_b(uid_hex)
            
            # 2. Auth using Key B (0x61)
            conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key_b)
            _, sw1, _ = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00])
            
            if sw1 == 0x90:
                # 3. Read Blocks 4, 5, 6
                blocks = []
                for b in [4, 5, 6]:
                    data, _, _ = conn.transmit([0xFF, 0xB0, 0x00, b, 0x10])
                    blocks.append(toHexString(data))
                
                print(f"[*] {label} ({uid_hex}) Captured.")
                # Wait for removal
                while True:
                    try:
                        time.sleep(0.5)
                        conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                    except: break
                return blocks
            else:
                # If Key B fails, maybe it's still using the Default Key?
                print(f"[-] Auth failed for {uid_hex}. Check your Key B logic.")
                return None
        except Exception: time.sleep(0.5)

def main():
    print("==========================================")
    print("      OpenCFS: TWIN SPOOL VALIDATOR       ")
    print("==========================================")
    
    s1_data = scan_one_tag("OWN SIDE 1 (LEFT)")
    if not s1_data: return
    
    s2_data = scan_one_tag("OWN SIDE 2 (RIGHT)")
    if not s2_data: return

    print("\n" + "="*60)
    print(f"{'BLOCK':<10} | {'SIDE 1 DATA':<20} | {'MATCH?'}")
    print("-" * 60)
    
    all_match = True
    for i, b_num in enumerate([4, 5, 6]):
        match = s1_data[i] == s2_data[i]
        status = "YES ✅" if match else "NO ❌"
        if not match: all_match = False
        print(f"Block {b_num:<5} | {s1_data[i][:20]:<20} | {status}")

    print("="*60)
    if all_match:
        print("\n🎉 VALIDATION SUCCESS: These tags are perfect twins.")
        print("[!] Final Step: Place them at the EXACT same rotation on the spool.")
    else:
        print("\n❌ VALIDATION FAILED: Data blocks do not match.")
        print("[!] Your cfs_writer.py is still generating different data per tag.")

if __name__ == "__main__":
    try: main()
    except KeyboardInterrupt: print("\nAborted.")
