import sys
import time
from smartcard.System import readers
from Crypto.Cipher import AES

# Creality Key Generator (exact zoals in je cfs_reader)
AES_KEY_GEN = bytes([0x71, 0x33, 0x62, 0x75, 0x5E, 0x74, 0x31, 0x6E, 0x71, 0x66, 0x5A, 0x28, 0x70, 0x66, 0x24, 0x31])

def generate_key_b(uid_hex):
    # Creality algoritme: UID herhalen tot 16 bytes
    uid_raw = bytes.fromhex(uid_hex.replace(" ", ""))
    uid_data = (uid_raw * 4)[:16]
    cipher = AES.new(AES_KEY_GEN, AES.MODE_ECB)
    return list(cipher.encrypt(uid_data)[:6])

def verify_tag_readiness():
    r = readers()
    if not r: 
        print("[-] Geen NFC lezer gevonden.")
        return
        
    # Pak de eerste beschikbare lezer uit de lijst
    reader = r[0] 
    conn = reader.createConnection()
    
    try:
        conn.connect()
        
        # 1. Haal UID op
        uid_res, _, _ = conn.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        uid_hex = "".join([f"{x:02X}" for x in uid_res])
        
        # 2. Bereken de unieke Key B voor DEZE tag
        cfs_key = generate_key_b(uid_hex)
        
        # 3. Laad de berekende Key B in de reader (Location 0x00)
        conn.transmit([0xFF, 0x82, 0x00, 0x00, 0x06] + cfs_key)
        
        # 4. Probeer te authenticeren op Blok 4 (Sector 1) met Key B (0x61)
        # [Direct Protocol, P1=0x00, P2=Blok, KeyType=0x61 (Key B), KeyLocation=0x00]
        resp, sw1, sw2 = conn.transmit([0xFF, 0x86, 0x00, 0x00, 0x05, 0x01, 0x00, 0x04, 0x61, 0x00])

        print(f"\n[🔍] ANALYSE TAG: {uid_hex}")
        print("═"*45)
        if sw1 == 0x90:
            print(" ✅  STATUS: KLAAR VOOR PRINTER")
            print("     De tag is correct beveiligd met de Creality Key B.")
            print("     De printer zou deze tag MOETEN herkennen.")
        else:
            print(" ❌  STATUS: NIET GEFORMATTEERD")
            print(f"     Foutcode: {hex(sw1)} {hex(sw2)}")
            print("     Oorzaak: Key B wordt geweigerd.")
            print("     Actie: Je moet eerst de juiste Key B schrijven.")
        print("═"*45 + "\n")

    except Exception as e:
        print(f"[-] Fout tijdens analyse: {e}")

if __name__ == "__main__":
    verify_tag_readiness()
