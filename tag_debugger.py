import time
import sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import AES

# --- KEYS FROM YOUR tag_reader.py ---
# Key used to derive the Sector 1 Key B (Hardware Auth)
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])
# Key used to decrypt the actual data blocks (Software Level)
AES_KEY_CIPHER = bytes([0x48, 0x40, 0x43, 0x46, 0x6B, 0x52, 0x6E, 0x7A, 0x40, 0x4B, 0x41, 0x74, 0x42, 0x4A, 0x70, 0x32])

def generate_key_b(uid_hex):
    """Calculates the unique Creality Key B for the specific Tag UID."""
    uid_data = bytes.fromhex((uid_hex * 4)[:32])
    cipher = AES.new(AES_KEY_GEN, AES.MODE_ECB)
    return list(cipher.encrypt(uid_data)[:6])

def run_debug():
    r = readers()
    if not r:
        print("[-] No reader found.")
        return
    
    conn = r[0].createConnection()
    print(">>> Waiting for Creality Spool...")

    while True:
        try:
            conn.connect()
            # 1. Get UID
            uid_raw, _, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            uid_hex = "".join([f"{x:02X}" for x in uid_raw])
            
            # 2. Calculate and Load Key B
            key_b = generate_key_b(uid_hex)
            conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key_b)

            # 3. Authenticate Sector 1 (Block 4)
            _, sw1, _ = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00])

            if sw1 == 0x90:
                print(f"\n[+] Tag UID: {uid_hex}")
                print(f"[+] Key B:   {toHexString(key_b)}")
                print("="*60)
                
                # Setup the Decrypter for the data blocks
                data_cipher = AES.new(AES_KEY_CIPHER, AES.MODE_ECB)
                
                for b in [4, 5, 6]:
                    # Read Raw Encrypted Block
                    raw_data, _, _ = conn.transmit([0xFF, 0xB0, 0x00, b, 0x10])
                    
                    # Decrypt the block
                    decrypted = data_cipher.decrypt(bytes(raw_data))
                    
                    # Clean up text for display
                    txt_display = "".join([chr(x) if 32 <= x <= 126 else "." for x in decrypted])
                    
                    print(f"BLOCK {b}")
                    print(f"  RAW: {toHexString(raw_data)}")
                    print(f"  DEC: {decrypted.hex().upper()}")
                    print(f"  TXT: {txt_display}")
                    print("-" * 40)
                
                # Read Trailer for Lock Status (Block 7)
                trailer, _, _ = conn.transmit([0xFF, 0xB0, 0x00, 0x07, 0x10])
                lock_status = "LOCKED (Read-Only)" if trailer[7:8] == 0x88 else "WRITABLE"
                print(f"BLOCK 7 (Trailer): {toHexString(trailer)}")
                print(f"STATUS: {lock_status}")
                print("="*60)
                break
            else:
                print(f"[-] Auth Failed for UID {uid_hex}. Not an original spool?")
                break
        except Exception:
            time.sleep(0.5)

if __name__ == "__main__":
    try:
        run_debug()
    except KeyboardInterrupt:
        sys.exit(0)
