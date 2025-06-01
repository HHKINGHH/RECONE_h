import sys
import time
import socket
import requests
import dns.resolver
import pandas as pd
import re
import whois
import os

from PySide6.QtWidgets import (
    QApplication, QWidget, QLabel, QLineEdit, QPushButton, QVBoxLayout,
    QMessageBox, QProgressBar, QListWidget, QHBoxLayout
)
from PySide6.QtCore import Qt, QThread, Signal

subdomains_list = ["www", "mail", "blog", "server", "support", "web", "store", "cdn", "api", "images", "mobile", "cloud"]
common_ports = [80, 443, 22, 25, 21, 8080, 3306, 53, 3389]

email_pattern = r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}"
phone_pattern = r"\+?[0-9]{7,15}"

def extract_info(url):
    try:
        response = requests.get(url, timeout=10)
        response.encoding = "utf-8"
        status_code = response.status_code
        content = response.text

        emails = set(re.findall(email_pattern, content))
        phones = set(re.findall(phone_pattern, content))

        return status_code, emails, phones
    except:
        return None, set(), set()

def get_whois_info(domain):
    try:
        info = whois.whois(domain)
        return info.creation_date, info.expiration_date, info.registrar
    except:
        return "نامشخص", "نامشخص", "نامشخص"

def scan_ports(host, ports):
    open_ports = []
    for port in ports:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((host, port))
            sock.close()
            if result == 0:
                open_ports.append(str(port))
        except:
            pass
    return "|".join(open_ports) if open_ports else "بدون پورت باز"

def check_subdomains_with_progress(domain, progress_callback):
    data = []
    emails_list = set()
    phones_list = set()

    start_url = f"https://{domain}"
    status, emails, phones = extract_info(start_url)
    creation_date, expiration_date, registrar = get_whois_info(domain)
    data.append([start_url, domain, status, "", creation_date, expiration_date, registrar])
    emails_list.update(emails)
    phones_list.update(phones)

    total = len(subdomains_list)
    for i, sub in enumerate(subdomains_list):
        subdomain = f"{sub}.{domain}"
        try:
            answers = dns.resolver.resolve(subdomain, "A")
            ip_list = [str(ip) for ip in answers]
            ip_str = "|".join(ip_list)
        except:
            ip_str = "یافت نشد"

        if ip_str != "یافت نشد":
            open_ports = scan_ports(subdomain, common_ports)
            status, emails, phones = extract_info(f"https://{subdomain}")
            creation_date, expiration_date, registrar = get_whois_info(subdomain)
            data.append([subdomain, ip_str, status, open_ports, creation_date, expiration_date, registrar])
            emails_list.update(emails)
            phones_list.update(phones)

        progress = int(((i+1) / total) * 80)
        progress_callback(progress)

    output_excel = "report.xlsx"
    output_text = "contacts.txt"

    df = pd.DataFrame(data, columns=["آدرس / زیردامنه", "آدرس IP", "وضعیت HTTP", "پورت‌های باز", "تاریخ ثبت", "تاریخ انقضا", "شرکت ثبت‌کننده"])
    df.to_excel(output_excel, index=False)

    with open(output_text, "w", encoding="utf-8") as f:
        f.write("لیست ایمیل‌های معتبر:\n")
        f.write("\n".join(sorted(emails_list)))
        f.write("\n\nلیست شماره‌های تلفن واقعی:\n")
        f.write("\n".join(sorted(phones_list)))

    progress_callback(80)
    return output_excel, output_text

common_files = [
    "backup.zip", "config.php", "admin.txt", "db_backup.sql", "passwords.txt",
    "secret.key", "dump.sql", "config.yaml", "config.json", "info.txt"
]

def file_enumeration_and_download(domain, progress_callback, download_folder="downloaded_files"):
    if not os.path.exists(download_folder):
        os.makedirs(download_folder)

    base_url = f"https://{domain}/"
    found_files = []

    total_files = len(common_files)
    for i, filename in enumerate(common_files):
        file_url = base_url + filename
        try:
            response = requests.get(file_url, timeout=5)
            if response.status_code == 200 and len(response.content) > 0:
                filepath = os.path.join(download_folder, filename)
                with open(filepath, "wb") as f:
                    f.write(response.content)
                found_files.append(filepath)
        except:
            pass
        progress = 80 + int(((i + 1) / total_files) * 20)
        progress_callback(progress)

    return found_files

class ScanThread(QThread):
    progress = Signal(int)
    finished = Signal(str, str, float, list)

    def __init__(self, domain):
        super().__init__()
        self.domain = domain

    def run(self):
        start_time = time.time()
        excel, txt = check_subdomains_with_progress(self.domain, self.progress.emit)
        found_files = file_enumeration_and_download(self.domain, self.progress.emit)
        elapsed = time.time() - start_time
        self.finished.emit(excel, txt, elapsed, found_files)

class LoginWindow(QWidget):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("ورود کاربر")
        self.resize(350, 180)

        self.setStyleSheet("""
            QWidget {
                background-color: #2c3e50;
                color: white;
                font-family: 'Segoe UI';
                font-size: 14px;
            }
            QLineEdit {
                padding: 8px;
                border-radius: 5px;
                border: 2px solid #2980b9;
                background-color: #34495e;
                color: white;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 red, stop:0.5 orange, stop:1 yellow);
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
                color: black;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 green, stop:0.5 blue, stop:1 purple);
            }
        """)

        layout = QVBoxLayout()

        label = QLabel("ثبت اطلاعات")
        label.setAlignment(Qt.AlignCenter)
        label.setStyleSheet("font-size: 18px; font-weight: bold; color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 red, stop:0.5 yellow, stop:1 green);")
        layout.addWidget(label)

        self.username_input = QLineEdit()
        layout.addWidget(self.username_input)

        self.login_button = QPushButton("ورود")
        self.login_button.clicked.connect(self.login)
        layout.addWidget(self.login_button)

        self.setLayout(layout)

    def login(self):
        username = self.username_input.text().strip()
        if not username:
            QMessageBox.warning(self, "هشدار", "لطفا نام کاربری را وارد کنید.")
            return
        self.main_window = MainWindow(username)
        self.main_window.show()
        self.close()

class MainWindow(QWidget):
    def __init__(self, username):
        super().__init__()
        self.setWindowTitle("اسکن دامنه")
        self.resize(500, 400)
        self.username = username

        self.setStyleSheet("""
            QWidget {
                background-color: #34495e;
                color: white;
                font-family: 'Segoe UI';
                font-size: 13px;
            }
            QLineEdit {
                padding: 8px;
                border-radius: 5px;
                border: 2px solid #2980b9;
                background-color: #2c3e50;
                color: white;
            }
            QPushButton {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 cyan, stop:0.5 magenta, stop:1 yellow);
                border: none;
                padding: 10px;
                border-radius: 5px;
                font-weight: bold;
            }
            QPushButton:hover {
                background: qlineargradient(x1:0, y1:0, x2:1, y2:0,
                    stop:0 red, stop:0.5 orange, stop:1 yellow);
            }
            QProgressBar {
                border: 2px solid #2980b9;
                border-radius: 5px;
                text-align: center;
                color: black;
                font-weight: bold;
            }
            QProgressBar::chunk {
                background-color: #27ae60;
                width: 20px;
            }
            QListWidget {
                background-color: #2c3e50;
                border: 1px solid #2980b9;
                color: white;
            }
        """)

        main_layout = QVBoxLayout()

        self.greeting = QLabel(f"خوش آمدی، {self.username}")
        self.greeting.setAlignment(Qt.AlignCenter)
        self.greeting.setStyleSheet("font-size: 16px; font-weight: bold; margin-bottom: 10px; color: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 red, stop:0.5 yellow, stop:1 green);")
        main_layout.addWidget(self.greeting)

        label = QLabel("دامنه را وارد کنید:")
        main_layout.addWidget(label)

        self.domain_input = QLineEdit()
        main_layout.addWidget(self.domain_input)

        self.start_button = QPushButton("شروع اسکن")
        self.start_button.clicked.connect(self.start_scan)
        main_layout.addWidget(self.start_button)

        self.progress_bar = QProgressBar()
        self.progress_bar.setValue(0)
        main_layout.addWidget(self.progress_bar)

        self.status_label = QLabel("")
        self.status_label.setAlignment(Qt.AlignCenter)
        main_layout.addWidget(self.status_label)

        file_list_label = QLabel("فایل‌های دانلود شده:")
        main_layout.addWidget(file_list_label)

        self.file_list_widget = QListWidget()
        main_layout.addWidget(self.file_list_widget)

        exit_button = QPushButton("خروج")
        exit_button.clicked.connect(self.close)
        exit_button.setStyleSheet("background-color: red; color: white; font-weight: bold;")
        main_layout.addWidget(exit_button)

        self.setLayout(main_layout)

    def start_scan(self):
        domain = self.domain_input.text().strip()
        if not domain:
            QMessageBox.warning(self, "هشدار", "لطفاً دامنه را وارد کنید.")
            return
        self.start_button.setEnabled(False)
        self.status_label.setText("در حال اسکن، لطفاً صبر کنید...")
        self.progress_bar.setValue(0)
        self.file_list_widget.clear()

        self.thread = ScanThread(domain)
        self.thread.progress.connect(self.progress_bar.setValue)
        self.thread.finished.connect(self.on_scan_finished)
        self.thread.start()

    def on_scan_finished(self, excel, txt, elapsed, found_files):
        self.status_label.setText(f"اسکن تمام شد! زمان تقریبی: {elapsed:.2f} ثانیه")
        self.start_button.setEnabled(True)

        QMessageBox.information(self, "پایان", f"گزارش‌ها ذخیره شدند:\n{excel}\n{txt}")

        if found_files:
            self.file_list_widget.addItems(found_files)
        else:
            self.file_list_widget.addItem("فایلی پیدا نشد.")

if __name__ == "__main__":
    app = QApplication(sys.argv)
    login_window = LoginWindow()
    login_window.show()
    sys.exit(app.exec())
