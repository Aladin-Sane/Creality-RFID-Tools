import time
import sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import AES

# The known Creality master key used to derive sector keys
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])

def generate_key_b(uid_hex):
    """Derives the Sector 1 Key B using the tag's UID."""
    uid_data = bytes.fromhex((uid_hex * 4)[:32])
    return list(AES.new(AES_KEY_GEN, AES.MODE_ECB).encrypt(uid_data)[:6])

def run_encrypted_dump():
    r = readers()
    if not r:
        print("[-] No reader found.")
        return
    
    conn = r[0].createConnection()
    print("="*50)
    print("🔍 CREALITY ENCRYPTED DATA DUMPER")
    print("="*50)
    print("[!] Place the tag on the reader...")

    while True:
        try:
            conn.connect()
            
            # 1. Get UID for key derivation
            uid_raw, _, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            uid_hex = "".join([f"{x:02X}" for x in uid_raw])
            key_b = generate_key_b(uid_hex)
            
            print(f"\n[+] Detected UID: {uid_hex}")
            print(f"[+] Using Key B:  {toHexString(key_b)}")

            # 2. Load Key B into the reader's volatile memory (Location 0x00)
            # Command: [FF 82 00 00 06] + 6-byte key
            conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key_b)

            # 3. Authenticate Sector 1 (specifically Block 4)
            # Command: [FF 86 00 00 05 01 00 Block KeyType KeyLoc]
            # KeyType 0x61 = Key B
            _, sw1, sw2 = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00])

            if sw1 == 0x90:
                print("\n--- SECTOR 1 RAW ENCRYPTED CONTENT ---")
                # Block 4: Material/Color Data
                # Block 5: Additional Metadata
                # Block 6: Usage/Stats Data
                # Block 7: Sector Trailer (Keys/Access Bits)
                for b in [4, 5, 6, 7]:
                    data, _, _ = conn.transmit([0xFF, 0xB0, 0x00, b, 0x10])
                    label = "DATA   " if b < 7 else "TRAILER"
                    print(f"Block {b} [{label}]: {toHexString(data)}")
                print("-" * 38)
                print("\n[✔] Raw data dump complete.")
                break
            else:
                print(f"[-] Auth Failed (SW: {sw1:02X} {sw2:02X}).")
                print("    This is likely not an original Creality tag.")
                break

        except Exception as e:
            # Silent retry to wait for the tag to be placed
            time.sleep(0.5)

if __name__ == "__main__":
    try:
        run_encrypted_dump()
    except KeyboardInterrupt:
        print("\n[!] Aborted by user.")
        sys.exit(0)
