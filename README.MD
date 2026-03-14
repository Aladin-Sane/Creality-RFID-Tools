# Creality RFID Tools: Complete Setup & Usage Guide

This repository provides a comprehensive toolset for analyzing, reading, and writing RFID tags compatible with the **Creality Filament System (CFS)** and **K2 Plus** printers.

### 🛠️ Hardware Requirements
To use these tools successfully, you must use hardware that matches the Creality ecosystem:
* **Reader:** [ACR122U NFC / RFID Smart Card Reader](https://www.acs.com.hk)
* **Tags:** 25mm NFC 1K S50 F08 Tag Stickers (Wet Inlay, 13.56MHz, ISO14443A)
  * *Note:* Both original NXP S50 and Fudan F08 chips are supported.

---

### ⚙️ System Installation & Driver Setup (Linux)
The ACR122U requires specific drivers and the blacklisting of conflicting kernel modules to work with Python via `pcsclite`.

**Step 2.1: Install Dependencies**
For Arch Linux / Manjaro:
`sudo pacman -S libnfc pcsclite pcsc-tools ccid acsccid`

**Step 2.2: Disable Conflicting Drivers**
The `pn533` and `nfc` kernel drivers often claim the device before the user-space tools can. You must block them.
* **To apply immediately:** `sudo modprobe -r pn533_usb pn533 nfc`
* **To apply permanently:** `echo -e "blacklist pn533\nblacklist pn533_usb\nblacklist nfc" | sudo tee /etc/modprobe.d/nfc-blacklist.conf`

**Step 2.3: Start the Smart Card Daemon**
`sudo systemctl enable --now pcscd.socket`

---

### 🐍 Python Environment Setup
It is recommended to run this toolset in a virtual environment (`venv`) to keep your system clean.
1. `git clone https://github.com/Aladin-Sane/Creality-RFID-Tools`
2. `cd Creality-RFID-Tools`
3. `python -m venv venv`
4. `source venv/bin/activate`
5. `pip install pyscard pycryptodome`

---

### 🚀 Toolset Overview

| Production Tools | Description |
| :--- | :--- |
| **tag_writer.py** | Write new filament/material data to a blank tag. |
| **tag_reader.py** | Reads and decodes the encrypted information from an existing Creality tag. |
| **tag_check.py** | Verifies if a tag is correctly encrypted and readable by the printer. |
| **spool_validator.py** | Reads both sides of a single spool to ensure the tags are identical. |

| Dev & Debug | Description |
| :--- | :--- |
| **tag_acceptor.py** | Determine if a generic tag's hardware (ATR/SAK) is compatible with the CFS. |
| **spool_analyser.py** | Detailed hardware analysis to identify chip type (NXP vs. Fudan). |
| **spool_comparer.py** | Reads tags from two different spools to compare data structures. |
| **tag_debugger.py** | Dumps raw hex data from all 16 sectors of the tag for deep analysis. |

---

### 📂 Project Structure
* **db/**: Contains material and color databases retrieved from the K2 Plus. **Crucial:** Keep these files synced with your printer's internal database.
* **venv/**: Local Python virtual environment (this should be ignored by git).

---

### Examples

See examples.txt
---

### ⚠️ Troubleshooting & Placement
The Creality CFS is highly sensitive to the physical positioning of the tags. If the printer is not reading your custom tags:
1. **Alignment:** Ensure the tag is placed exactly where the original tag is.
2. **Interference:** if detection is slow (or none), you may need "on-metal" shielded tags.
3. **Encrypted Data:** Ensure the data written to the tag matches a valid material entry in the `db/` folder.

---

### 🤝 Contributing
Contributions are welcome! If you find new material IDs or have code improvements, please fork the repository and open a Pull Request.

---

### 📜 License
**MIT License**
Copyright (c) 2026 Aladin-Sane
Permission is hereby granted, free of charge, to any person obtaining a copy of this software and associated documentation files (the "Software"), to deal in the Software without restriction, including without limitation the rights to use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of the Software, and to permit persons to whom the Software is furnished to do so, subject to the following conditions:
The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.
THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
