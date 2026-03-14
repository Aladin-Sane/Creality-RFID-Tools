#Creality RFID Tools

Toolset to write your own RFID tags, readable by Creality's CFS / RFID reader.


Hardware:
- ACR122U RFID IC Smart Card Reader
- 25Mm Nfc 1K S50 F08 Tag Stickers Wet Inlay 13.56Mhz ISO14443A

Pre-requisites:
Install required packages
- sudo pacman -S libnfc pcsclite pcsc-tools ccid acsccid

Blacklist conflicting kernel drivers (effective next boot)
- echo -e "blacklist pn533\nblacklist pn533_usb\nblacklist nfc" | sudo tee /etc/modprobe.d/nfc-blacklist.conf

Bblacklist conflicting kernel drivers (effective now, still have todo the line above....)
- sudo modprobe -r pn533_usb pn533 nfc

Restart pcscdeamon
- systemctl enable --now pcscd.socket


! Toolset runs in python, venv.
! directory db/ contains matrial and color databases. Material is retrieved from my K2 Plus, this file might be updated, keep in sync with your printers one ;)


Howto install/use:
- git clone https://github.com/Aladin-Sane/Creality-RFID-Tools 
- cd Creality-RFID-Tools
- source venv/bin/activate
- run a python script.


Toolset:
- spool_validator.py     - reads both sides of 1 spool, and reports if both tags are identical
- tag_reader.py          - reads info from a tag
- tag_writer.py          - write new tag
- tag_check.py           - checks if tag is correctly encrypted


Testing/Development scripts:
- spool_analyser.py      - read rfid tag, and (tries to) determine what tag is used
- spool_comparer.py      - reads both sides of 2 spools, and compares them
- tag_acceptor.py        - Determines if the tag is compatible with Creality CFS
- tag_debugger.py        - Reads raw data from tag


Currently, my CFS is not (yet) reading my tags, might be that i need the metalic-ones, or the exact location on the spools is not correct yet, work in progres :)



