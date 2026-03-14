import sys
from smartcard.CardRequest import CardRequest
from smartcard.Exceptions import CardRequestTimeoutException
from smartcard.CardType import AnyCardType

def analyse_original_spool():
    print("\n" + "="*50)
    print("CREALITY SPOOL ANALYZER")
    print("="*50)
    print("[!] Please place the tag on the scanner...")
    
    # Configure request to wait for ANY card type
    card_type = AnyCardType()
    
    # timeout=None makes the program wait indefinitely until a card is present
    request = CardRequest(timeout=None, cardType=card_type)
    
    try:
        # This line blocks the script until a card is detected
        service = request.waitforcard()
    except Exception as e:
        print(f"[-] Error waiting for card: {e}")
        return

    # Use the connection provided by the detected card service
    connection = service.connection
    
    try:
        connection.connect()
        
        # 1. ATR (Answer To Reset) - The hardware identity
        atr = connection.getATR()
        atr_hex = " ".join([f"{x:02X}" for x in atr])
        
        # 2. UID (Unique ID)
        uid_res, _, _ = connection.transmit([0xFF, 0xCA, 0x00, 0x00, 0x00])
        uid_hex = " ".join([f"{x:02X}" for x in uid_res])

        # 3. SAK (Select Acknowledge) - Crucial for chip-type
        # PCSC command for ACR122U to retrieve SAK
        sak_res, _, _ = connection.transmit([0xFF, 0xCA, 0x01, 0x00, 0x00])
        sak_hex = " ".join([f"{x:02X}" for x in sak_res])

        print("\n" + "="*50)
        print("ANALISYS SPOOL")
        print("="*50)
        print(f"🆔 UID:  {uid_hex}")
        print(f"📜 ATR:  {atr_hex}")
        print(f"🔑 SAK:  {sak_hex}")
        print("="*50)
        
        # Interpretation
        if "08" in sak_hex:
            print("Chip Type: MIFARE Classic 1K (S50)")
        elif "88" in sak_hex:
            print("Chip Type: MIFARE Classic 1K (Infineon of NXP EV1)")
        else:
            print("Chip Type: Unknown / Other RFID Tag")
            
        print("\n[!] Copy this output and paste it where needed!")

    except Exception as e:
        print(f"[-] Error during communication: {e}")

if __name__ == '__main__':
    try:
        analyse_original_spool()
    except KeyboardInterrupt:
        # Allows you to exit the waiting state with Ctrl+C
        print("\n[!] Program stopped by user.")
        sys.exit()
