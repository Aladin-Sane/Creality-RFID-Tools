import time
import sys
from smartcard.System import readers
from smartcard.util import toHexString
from Crypto.Cipher import AES

AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])

def generate_key_b(uid_hex):
    uid_data = bytes.fromhex((uid_hex * 4)[:32])
    return list(AES.new(AES_KEY_GEN, AES.MODE_ECB).encrypt(uid_data)[:6])

def run_debug():
    r = readers()
    if not r: return
    conn = r[0].createConnection()
    
    print(">>> Place ORIGINAL Spool on reader...")
    while True:
        try:
            conn.connect()
            # 1. Get UID
            uid_raw, _, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
            uid_hex = "".join([f"{x:02X}" for x in uid_raw])
            key_b = generate_key_b(uid_hex)
            
            print(f"\n[!] Tag UID: {uid_hex}")
            print(f"[!] Calc Key B: {toHexString(key_b)}")

            # 2. Auth Sector 1 (Block 4) using Key B (0x61)
            conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + key_b)
            _, sw1, _ = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00])

            if sw1 == 0x90:
                print("-" * 30)
                for b in [4, 5, 6, 7]: # Includes the Trailer (Block 7)
                    data, _, _ = conn.transmit([0xFF, 0xB0, 0x00, b, 0x10])
                    label = "DATA" if b < 7 else "TRAILER"
                    print(f"Block {b} ({label}): {toHexString(data)}")
                print("-" * 30)
                break
            else:
                print("[-] Auth Failed. Is this a genuine Creality tag?")
                break
        except Exception: time.sleep(0.5)

if __name__ == "__main__":
    run_debug()
