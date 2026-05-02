import ctypes
import ipaddress
import queue
import re
import sys
import time
from dataclasses import dataclass
from datetime import datetime
from typing import Dict, Optional, Set, Tuple

from PyQt6.QtCore import QThread, pyqtSignal
from PyQt6.QtWidgets import (
    QApplication,
    QComboBox,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)
from scapy.all import ARP, AsyncSniffer


MAC_PATTERN = re.compile(r"^(?:[0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$")


def is_admin() -> bool:
    """Check whether the process has elevated privileges."""
    if sys.platform.startswith("win"):
        try:
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        except Exception:
            return False
    try:
        import os

        return os.geteuid() == 0
    except Exception:
        return False


def normalize_mac(mac: str) -> str:
    return mac.lower()


def is_valid_mac(mac: str) -> bool:
    return bool(MAC_PATTERN.match(mac.strip()))


def is_valid_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


@dataclass
class ArpEvent:
    timestamp: datetime
    src_ip: str
    src_mac: str
    target_ip: str
    op_name: str


class ArpAnalyzer:
    """Tracks ARP mappings and flags high-signal anomalies."""

    def __init__(self):
        self.ip_to_mac: Dict[str, str] = {}
        self.mac_to_ip: Dict[str, str] = {}
        self.seen_pairs: Set[Tuple[str, str]] = set()
        self.counters = {
            "packets": 0,
            "new_pairs": 0,
            "ip_conflicts": 0,
            "mac_conflicts": 0,
        }

    def process(self, event: ArpEvent):
        alerts = []
        self.counters["packets"] += 1
        pair = (event.src_ip, event.src_mac)

        if pair not in self.seen_pairs:
            self.seen_pairs.add(pair)
            self.counters["new_pairs"] += 1

        existing_mac = self.ip_to_mac.get(event.src_ip)
        if existing_mac and existing_mac != event.src_mac:
            self.counters["ip_conflicts"] += 1
            alerts.append(
                f"ALERT: IP conflict detected for {event.src_ip}: "
                f"{existing_mac} -> {event.src_mac}"
            )
        self.ip_to_mac[event.src_ip] = event.src_mac

        existing_ip = self.mac_to_ip.get(event.src_mac)
        if existing_ip and existing_ip != event.src_ip:
            self.counters["mac_conflicts"] += 1
            alerts.append(
                f"ALERT: MAC conflict detected for {event.src_mac}: "
                f"{existing_ip} -> {event.src_ip}"
            )
        self.mac_to_ip[event.src_mac] = event.src_ip

        return alerts

    def get_stats_text(self) -> str:
        return (
            f"packets={self.counters['packets']} | "
            f"new_pairs={self.counters['new_pairs']} | "
            f"ip_conflicts={self.counters['ip_conflicts']} | "
            f"mac_conflicts={self.counters['mac_conflicts']}"
        )


class ArpMonitorWorker(QThread):
    log = pyqtSignal(str)
    stats = pyqtSignal(str)

    def __init__(
        self,
        interface: str,
        watch_ip: Optional[str],
        poll_interval: float,
    ):
        super().__init__()
        self.interface = interface
        self.watch_ip = watch_ip
        self.poll_interval = poll_interval
        self._running = True
        self._events: "queue.Queue[ArpEvent]" = queue.Queue(maxsize=4096)
        self._analyzer = ArpAnalyzer()
        self._sniffer: Optional[AsyncSniffer] = None

    def _handle_packet(self, packet):
        if not packet.haslayer(ARP):
            return

        arp = packet[ARP]
        src_ip = str(arp.psrc)
        src_mac = normalize_mac(str(arp.hwsrc))
        target_ip = str(arp.pdst)
        op_name = "reply" if int(arp.op) == 2 else "request"

        if not is_valid_ip(src_ip) or not is_valid_mac(src_mac):
            return

        if self.watch_ip and self.watch_ip not in (src_ip, target_ip):
            return

        event = ArpEvent(
            timestamp=datetime.now(),
            src_ip=src_ip,
            src_mac=src_mac,
            target_ip=target_ip,
            op_name=op_name,
        )

        try:
            self._events.put_nowait(event)
        except queue.Full:
            self.log.emit("WARN: Event queue is full, dropping ARP packet.")

    def run(self):
        self.log.emit(
            f"Starting ARP monitor on interface='{self.interface}' "
            f"with poll interval={self.poll_interval:.1f}s"
        )

        if self.watch_ip:
            self.log.emit(f"Focus mode enabled for IP {self.watch_ip}")

        try:
            self._sniffer = AsyncSniffer(
                iface=self.interface,
                filter="arp",
                prn=self._handle_packet,
                store=False,
            )
            self._sniffer.start()
            self.log.emit("Packet capture started.")

            while self._running:
                processed = 0
                while not self._events.empty() and processed < 500:
                    event = self._events.get_nowait()
                    processed += 1

                    alerts = self._analyzer.process(event)
                    self.log.emit(
                        f"[{event.timestamp.strftime('%H:%M:%S')}] "
                        f"{event.op_name.upper()} "
                        f"{event.src_ip} is-at {event.src_mac} "
                        f"for {event.target_ip}"
                    )
                    for alert in alerts:
                        self.log.emit(alert)

                self.stats.emit(self._analyzer.get_stats_text())
                time.sleep(self.poll_interval)

        except Exception as exc:
            self.log.emit(f"ERROR: monitor failure: {exc}")
        finally:
            if self._sniffer is not None:
                try:
                    self._sniffer.stop()
                except Exception:
                    pass
            self.stats.emit(self._analyzer.get_stats_text())
            self.log.emit("ARP monitor stopped.")

    def stop(self):
        self._running = False


class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ARP Security Monitor")
        self.setMinimumSize(820, 560)
        self.worker: Optional[ArpMonitorWorker] = None

        central = QWidget()
        layout = QVBoxLayout(central)
        self.setCentralWidget(central)

        config_group = QGroupBox("Capture Configuration")
        config_layout = QVBoxLayout()

        row1 = QHBoxLayout()
        row1.addWidget(QLabel("Interface:"))
        self.interface_input = QLineEdit()
        self.interface_input.setPlaceholderText("e.g., Ethernet, Wi-Fi, eth0")
        row1.addWidget(self.interface_input)
        config_layout.addLayout(row1)

        row2 = QHBoxLayout()
        row2.addWidget(QLabel("Watch IP (optional):"))
        self.watch_ip_input = QLineEdit()
        self.watch_ip_input.setPlaceholderText("e.g., 192.168.1.1")
        row2.addWidget(self.watch_ip_input)
        config_layout.addLayout(row2)

        row3 = QHBoxLayout()
        row3.addWidget(QLabel("Analysis Profile:"))
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("High Throughput (0.2s)", 0.2)
        self.profile_combo.addItem("Balanced (0.5s)", 0.5)
        self.profile_combo.addItem("Low CPU (1.0s)", 1.0)
        self.profile_combo.setCurrentIndex(1)
        row3.addWidget(self.profile_combo)
        config_layout.addLayout(row3)

        config_group.setLayout(config_layout)
        layout.addWidget(config_group)

        btn_row = QHBoxLayout()
        self.start_button = QPushButton("Start Monitoring")
        self.start_button.clicked.connect(self.start_monitoring)
        self.start_button.setStyleSheet(
            "QPushButton { background-color: #0A7A3F; color: white; "
            "font-weight: bold; padding: 8px; }"
        )
        btn_row.addWidget(self.start_button)

        self.stop_button = QPushButton("Stop Monitoring")
        self.stop_button.clicked.connect(self.stop_monitoring)
        self.stop_button.setEnabled(False)
        self.stop_button.setStyleSheet(
            "QPushButton { background-color: #A11A1A; color: white; "
            "font-weight: bold; padding: 8px; }"
        )
        btn_row.addWidget(self.stop_button)
        layout.addLayout(btn_row)

        self.stats_label = QLabel("stats: packets=0 | new_pairs=0 | ip_conflicts=0 | mac_conflicts=0")
        layout.addWidget(self.stats_label)

        layout.addWidget(QLabel("Live ARP Event Stream:"))
        self.output = QTextEdit()
        self.output.setReadOnly(True)
        layout.addWidget(self.output)

        self.print_output("=== ARP Security Monitor ===")
        self.print_output("Purpose: detect ARP spoofing indicators and mapping anomalies.")
        if not is_admin():
            self.print_output("WARNING: Capture privileges are not elevated. Sniffing may fail.")

    def start_monitoring(self):
        interface = self.interface_input.text().strip()
        watch_ip = self.watch_ip_input.text().strip() or None
        poll_interval = float(self.profile_combo.currentData())

        if not interface:
            self.print_output("ERROR: Interface is required.")
            return

        if watch_ip and not is_valid_ip(watch_ip):
            self.print_output("ERROR: Watch IP is invalid.")
            return

        if self.worker is not None and self.worker.isRunning():
            self.print_output("ERROR: Monitor is already running.")
            return

        self.worker = ArpMonitorWorker(
            interface=interface,
            watch_ip=watch_ip,
            poll_interval=poll_interval,
        )
        self.worker.log.connect(self.print_output)
        self.worker.stats.connect(self.update_stats)

        self.interface_input.setEnabled(False)
        self.watch_ip_input.setEnabled(False)
        self.profile_combo.setEnabled(False)
        self.start_button.setEnabled(False)
        self.stop_button.setEnabled(True)

        self.print_output("Initializing monitor...")
        self.worker.start()

    def stop_monitoring(self):
        if self.worker is None:
            self.print_output("ERROR: Monitor is not running.")
            return

        self.print_output("Stopping monitor...")
        try:
            self.worker.stop()
            self.worker.wait(4000)
        except Exception as exc:
            self.print_output(f"ERROR: {exc}")
        finally:
            self.worker = None
            self.interface_input.setEnabled(True)
            self.watch_ip_input.setEnabled(True)
            self.profile_combo.setEnabled(True)
            self.start_button.setEnabled(True)
            self.stop_button.setEnabled(False)
            self.print_output("Monitor stopped.")

    def update_stats(self, stats_text: str):
        self.stats_label.setText(f"stats: {stats_text}")

    def print_output(self, message: str):
        self.output.append(message)

    def closeEvent(self, event):
        if self.worker is not None and self.worker.isRunning():
            self.stop_monitoring()
        event.accept()


if __name__ == "__main__":
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())