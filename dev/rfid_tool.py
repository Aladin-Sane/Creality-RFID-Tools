import sys
from PySide6.QtWidgets import (QApplication, QMainWindow, QTabWidget, QWidget, 
                             QVBoxLayout, QPushButton, QTextEdit, QLabel, QTableWidget, QTableWidgetItem)
from PySide6.QtSerialPort import QSerialPortInfo

class DeviceTab(QWidget):
    """5th Tab: Displays information about connected RFID Reader/Writer hardware."""
    def __init__(self):
        super().__init__()
        layout = QVBoxLayout()
        
        self.info_label = QLabel("Connected RFID Hardware:")
        self.device_table = QTableWidget(0, 3)
        self.device_table.setHorizontalHeaderLabels(["Port", "Manufacturer", "Hardware ID"])
        
        self.refresh_btn = QPushButton("Scan for Devices")
        self.refresh_btn.clicked.connect(self.scan_devices)
        
        layout.addWidget(self.info_label)
        layout.addWidget(self.device_table)
        layout.addWidget(self.refresh_btn)
        self.setLayout(layout)
        self.scan_devices()

    def scan_devices(self):
        """Scans serial ports for common RFID reader/writer hardware."""
        self.device_table.setRowCount(0)
        available_ports = QSerialPortInfo.availablePorts()
        
        for port in available_ports:
            row = self.device_table.rowCount()
            self.device_table.insertRow(row)
            self.device_table.setItem(row, 0, QTableWidgetItem(port.portName()))
            self.device_table.setItem(row, 1, QTableWidgetItem(port.manufacturer() or "Unknown"))
            self.device_table.setItem(row, 2, QTableWidgetItem(f"{port.vendorIdentifier():04x}:{port.productIdentifier():04x}"))

class ScriptTab(QWidget):
    """Standard tab for the 4 core scripts (Read, Generate, Write, Verify)."""
    def __init__(self, script_name):
        super().__init__()
        layout = QVBoxLayout()
        self.label = QLabel(f"Tool: {script_name}")
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        self.run_btn = QPushButton(f"Run {script_name}")
        
        layout.addWidget(self.label)
        layout.addWidget(self.run_btn)
        layout.addWidget(self.output)
        self.setLayout(layout)

class CrealityRFIDApp(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Creality RFID Production Suite")
        self.resize(850, 600)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        # Core 4 Scripts
        self.tabs.addTab(ScriptTab("RFID Reader"), "Read")
        self.tabs.addTab(ScriptTab("Dump Generator"), "Generate")
        self.tabs.addTab(ScriptTab("RFID Writer"), "Write")
        self.tabs.addTab(ScriptTab("Verification Tool"), "Verify")
        
        # New 5th Tab for Hardware Info
        self.tabs.addTab(DeviceTab(), "Hardware Info")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = CrealityRFIDApp()
    window.show()
    sys.exit(app.exec())
