import tkinter as tk
from tkinter import ttk, scrolledtext
import subprocess
import time
from pynput import mouse
import psutil
import threading
import socket
from datetime import datetime
import winsound

class AnomalyDetectionGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Anomaly Detection System")
        self.geometry("1000x650")
        self.configure(bg="#f4f6f8")  # Carbon Background color

        self.detecting = False
        self.last_failed_login_time = None
        self.known_ips = set()
        self.click_times = []

        # Create header
        self.header = tk.Frame(self, bg="#0063B1", height=50)
        self.header.grid(row=0, column=0, sticky="ew", columnspan=3)
        self.header.grid_propagate(False)

        # Title label in header
        self.title_label = tk.Label(self.header, text="Anomaly Detection Dashboard", font=("Arial", 18, "bold"), fg="#ffffff", bg="#0063B1")
        self.title_label.pack(pady=10)

        # Main Content Frame
        self.content_frame = tk.Frame(self, bg="#f4f6f8")
        self.content_frame.grid(row=1, column=0, padx=20, pady=20, sticky="nsew")
        self.content_frame.grid_rowconfigure(0, weight=1)
        self.content_frame.grid_columnconfigure(0, weight=1)

        # Log Display (right side of the dashboard)
        self.log_display = scrolledtext.ScrolledText(self.content_frame, bg="#252526", fg="#ffffff", font=("Arial", 10), bd=0, wrap=tk.WORD)
        self.log_display.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")

        # Control panel on the left side
        self.control_panel = tk.Frame(self.content_frame, bg="#ffffff", relief="solid", bd=1, padx=20, pady=20)
        self.control_panel.grid(row=0, column=0, sticky="nsew", padx=10)

        # Start Button
        self.start_btn = ttk.Button(self.control_panel, text="Start", command=self.start_detection, width=20)
        self.start_btn.grid(row=0, column=0, pady=10)

        # Stop Button
        self.stop_btn = ttk.Button(self.control_panel, text="Stop", command=self.stop_detection, width=20)
        self.stop_btn.grid(row=1, column=0, pady=10)

        # Clear Logs Button
        self.clear_btn = ttk.Button(self.control_panel, text="Clear Logs", command=self.clear_logs, width=20)
        self.clear_btn.grid(row=2, column=0, pady=10)

        # Export Logs Button
        self.export_btn = ttk.Button(self.control_panel, text="Export Logs", command=self.export_logs, width=20)
        self.export_btn.grid(row=3, column=0, pady=10)

        # Status Bar at the bottom
        self.status_bar = tk.Label(self, text="Status: Monitoring...", bd=1, relief=tk.SUNKEN, anchor="w", bg="#0063B1", fg="#ffffff")
        self.status_bar.grid(row=2, column=0, sticky="ew", padx=10, pady=5)

        # Set grid configuration for responsiveness
        self.grid_rowconfigure(1, weight=1)  # Content area expands
        self.grid_columnconfigure(0, weight=1)  # Main layout expands
        self.grid_columnconfigure(1, weight=3)  # Log display section expands

    def update_log(self, message, color="#ffffff"):
        """ Update log display with a slight fade-in effect for animation """
        self.log_display.insert(tk.END, message + "\n")
        self.log_display.yview(tk.END)

    def start_detection(self):
        if not self.detecting:
            self.detecting = True
            self.update_log("[INFO] Detection started...", "#00cc66")
            self.status_bar.config(text="Status: Detection in progress...", fg="#00cc66")
            threading.Thread(target=self.detect_resource_usage, daemon=True).start()
            threading.Thread(target=self.detect_failed_logins, daemon=True).start()
            threading.Thread(target=self.detect_mouse_activity, daemon=True).start()
            threading.Thread(target=self.detect_network_change, daemon=True).start()

    def stop_detection(self):
        self.detecting = False
        self.update_log("[INFO] Detection stopped.", "#ffcc00")
        self.status_bar.config(text="Status: Detection stopped.", fg="#ffcc00")

    def clear_logs(self):
        self.log_display.delete('1.0', tk.END)

    def export_logs(self):
        with open("logs.txt", "w") as file:
            file.write(self.log_display.get('1.0', tk.END))
        self.update_log("[INFO] Logs exported to logs.txt", "#00cc66")

    ### ✅ CPU & Memory Usage Detection ✅
    def detect_resource_usage(self):
        while self.detecting:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent

            if cpu_usage > 80:
                self.update_log(f"[ALERT] High CPU usage detected: {cpu_usage}%", "#ff3333")
                winsound.Beep(1000, 500)  # Sound Alert
            if memory_usage > 80:
                self.update_log(f"[ALERT] High memory usage detected: {memory_usage}%", "#ff3333")
                winsound.Beep(1000, 500)  # Sound Alert

            time.sleep(1)

    ### ✅ Failed Login Attempts Detection ✅
    def detect_failed_logins(self):
        try:
            while self.detecting:
                output = subprocess.check_output(
                    ["powershell.exe", 
                     "Get-WinEvent -FilterHashtable @{LogName='Security';ID=4625} | Select-Object TimeCreated, Message"],
                    stderr=subprocess.DEVNULL
                ).decode('utf-8')

                events = output.strip().split('\n')[3:]  # Skip header lines

                for event in events:
                    if event.strip():
                        parts = event.split()
                        time_created = ' '.join(parts[:2])

                        try:
                            event_time = datetime.strptime(time_created, '%m/%d/%Y %I:%M:%S %p')
                            if self.last_failed_login_time is None or event_time > self.last_failed_login_time:
                                self.last_failed_login_time = event_time
                                self.update_log(f"[ALERT] Failed login attempt detected at {event_time}", "#ff3333")
                                winsound.Beep(1000, 500)  # Sound Alert
                        except Exception as e:
                            pass

                time.sleep(5)

        except subprocess.CalledProcessError:
            self.update_log("[ERROR] Failed to read logs (Permissions issue?)", "#ff0000")
        except Exception as e:
            self.update_log(f"[ERROR] Failed to monitor login attempts: {e}", "#ff0000")

    ### ✅ Rapid Mouse Clicks Detection ✅
    def on_click(self, x, y, button, pressed):
        if pressed:
            self.click_times.append(time.time())
            self.click_times = self.click_times[-10:]

            if len(self.click_times) >= 5 and self.click_times[-1] - self.click_times[-5] < 1:
                self.update_log("[ALERT] Suspicious rapid mouse clicks detected!", "#ff3333")
                winsound.Beep(1000, 500)  # Sound Alert

    def detect_mouse_activity(self):
        with mouse.Listener(on_click=self.on_click) as listener:
            listener.join()

    ### ✅ Network Change Detection ✅
    def detect_network_change(self):
        try:
            while self.detecting:
                new_ips = set()
                hostname = socket.gethostname()
                ip = socket.gethostbyname(hostname)

                new_ips.add(ip)
                for interface, addrs in psutil.net_if_addrs().items():
                    for addr in addrs:
                        if addr.family == socket.AF_INET:
                            new_ips.add(addr.address)

                new_connections = new_ips - self.known_ips
                if new_connections:
                    for new_ip in new_connections:
                        self.update_log(f"[ALERT] New network connection detected: {new_ip}", "#ff3333")
                        winsound.Beep(1000, 500)  # Sound Alert

                self.known_ips = new_ips
                time.sleep(5)
        except Exception as e:
            self.update_log(f"[ERROR] Failed to monitor network changes: {e}", "#ff0000")


if __name__ == "__main__":
    app = AnomalyDetectionGUI()
    app.mainloop()
