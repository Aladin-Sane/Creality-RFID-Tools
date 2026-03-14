import sys
import time
from smartcard.CardRequest import CardRequest
from smartcard.CardType import AnyCardType
from smartcard.Exceptions import CardRequestTimeoutException, NoCardException, CardConnectionException

def run_cfs_verifier():
    card_type = AnyCardType()
    card_request = CardRequest(timeout=None, cardType=card_type)
    
    print("="*50)
    print("🚀 CREALITY CFS HARDWARE VERIFIER")
    print("="*50)
    print("[!] Wachten op tag... (Leg een tag op de scanner)\n")

    try:
        while True:
            try:
                cardservice = card_request.waitforcard()
                cardservice.connection.connect()

                # 1. Get UID
                uid_res, _, _ = cardservice.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                uid_hex = " ".join([f"{x:02X}" for x in uid_res])
                
                # 2. Get ATR (This is what we use for verification now)
                atr = cardservice.connection.getATR()
                atr_hex = " ".join([f"{x:02X}" for x in atr])

                # 3. CFS Compatibility Logic based on your ATR
                # Your ATR: 3B 8F 80 01 80 4F 0C A0 00 00 03 06 03 00 01 00 00 00 00 6A
                # '03 00 01' is the classic signature for MIFARE 1K
                is_compatible = False
                if "03 00 01" in atr_hex:
                    chip_name = "MIFARE Classic 1K (S50) / Fudan F08"
                    is_compatible = True
                else:
                    chip_name = "Unknown or Incompatible Tag Type"

                print("═"*50)
                print(f"🆔 UID:  {uid_hex}")
                print(f"📜 ATR:  {atr_hex}")
                print(f"📟 TYPE: {chip_name}")
                
                if is_compatible:
                    print("✅ STATUS: GESCHIKT (CFS COMPATIBEL)")
                    print("   Dit is de juiste hardware voor de Creality CFS.")
                else:
                    print("❌ STATUS: NIET GESCHIKT")
                print("═"*50)
                
                print("\n[!] Haal de tag weg voor de volgende scan...")

                while True:
                    time.sleep(0.5)
                    try:
                        cardservice.connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
                    except (NoCardException, CardConnectionException):
                        print("[✔] Scanner weer vrij.\n")
                        break

            except (CardRequestTimeoutException, NoCardException, CardConnectionException):
                continue

    except KeyboardInterrupt:
        print("\n\n[!] Gestopt door gebruiker.")
        sys.exit(0)

if __name__ == "__main__":
    run_cfs_verifier()
