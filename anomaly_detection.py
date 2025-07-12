import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox
import threading
import time
import psutil
import socket
import winsound
from datetime import datetime
from pynput import mouse
import subprocess
import pyttsx3
import matplotlib.pyplot as plt
from matplotlib.backends.backend_tkagg import FigureCanvasTkAgg

class AnomalyDetectionGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Anomaly Detection System")
        self.geometry("1200x800")
        self.configure(bg="#f4f6f8")

        # Variables
        self.detecting = False
        self.known_ips = set()
        self.click_times = []
        self.last_failed_login_time = None

        # AI voice alert setup
        self.voice = pyttsx3.init()
        self.voice.setProperty('rate', 180)

        # Header
        self.header = tk.Frame(self, bg="#003366", height=60)
        self.header.pack(fill="x")
        self.title_label = tk.Label(self.header, text="🔍 Advanced Anomaly Detection System", font=("Arial", 20, "bold"), fg="#ffffff", bg="#003366")
        self.title_label.pack(pady=10)

        # Main content
        self.content_frame = tk.Frame(self, bg="#f4f6f8")
        self.content_frame.pack(fill="both", expand=True, padx=20, pady=10)

        # Log display
        self.log_display = scrolledtext.ScrolledText(self.content_frame, bg="#252526", fg="#ffffff", font=("Arial", 10), wrap=tk.WORD)
        self.log_display.pack(side="right", fill="both", expand=True, padx=10)

        # Control panel
        self.control_panel = tk.Frame(self.content_frame, bg="#ffffff", relief="solid", bd=1, padx=20, pady=20)
        self.control_panel.pack(side="left", fill="y")

        # Buttons
        self.start_btn = ttk.Button(self.control_panel, text="Start Detection", command=self.start_detection, width=20)
        self.start_btn.pack(pady=10)

        self.stop_btn = ttk.Button(self.control_panel, text="Stop Detection", command=self.stop_detection, width=20)
        self.stop_btn.pack(pady=10)

        self.clear_btn = ttk.Button(self.control_panel, text="Clear Logs", command=self.clear_logs, width=20)
        self.clear_btn.pack(pady=10)

        self.export_btn = ttk.Button(self.control_panel, text="Export Logs", command=self.export_logs, width=20)
        self.export_btn.pack(pady=10)

        # Status Bar
        self.status_bar = tk.Label(self, text="Status: Idle", bd=1, relief=tk.SUNKEN, anchor="w", bg="#003366", fg="#ffffff")
        self.status_bar.pack(side="bottom", fill="x")

        # Visualization
        self.create_charts()

    def create_charts(self):
        self.chart_frame = tk.Frame(self, bg="#f4f6f8")
        self.chart_frame.pack(side="bottom", fill="x", padx=10, pady=10)

        fig, self.ax = plt.subplots(1, 2, figsize=(12, 5))
        
        self.cpu_data = []
        self.memory_data = []

        self.ax[0].set_title("CPU Usage (%)")
        self.ax[1].set_title("Memory Usage (%)")

        for ax in self.ax:
            ax.set_ylim(0, 100)
            ax.set_xlabel("Time")
            ax.set_ylabel("Usage")

        self.canvas = FigureCanvasTkAgg(fig, master=self.chart_frame)
        self.canvas.get_tk_widget().pack(fill="both", expand=True)
        threading.Thread(target=self.update_chart, daemon=True).start()

    def update_chart(self):
        while True:
            if self.detecting:
                self.cpu_data.append(psutil.cpu_percent())
                self.memory_data.append(psutil.virtual_memory().percent)

                if len(self.cpu_data) > 20:
                    self.cpu_data.pop(0)
                    self.memory_data.pop(0)

                self.ax[0].cla()
                self.ax[1].cla()

                self.ax[0].plot(self.cpu_data, label="CPU Usage", color="blue")
                self.ax[1].plot(self.memory_data, label="Memory Usage", color="green")

                self.ax[0].legend()
                self.ax[1].legend()

                self.canvas.draw()

            time.sleep(2)

    def update_log(self, message, color="#ffffff"):
        self.log_display.insert(tk.END, message + "\n")
        self.log_display.yview(tk.END)
        self.voice.say(message)
        self.voice.runAndWait()

    def start_detection(self):
        if not self.detecting:
            self.detecting = True
            self.status_bar.config(text="Status: Monitoring...", fg="#00cc66")
            self.update_log("[INFO] Detection started...", "#00cc66")

            # Start detection threads
            threading.Thread(target=self.detect_resource_usage, daemon=True).start()
            threading.Thread(target=self.detect_mouse_activity, daemon=True).start()
            threading.Thread(target=self.detect_network_change, daemon=True).start()
            threading.Thread(target=self.detect_failed_logins, daemon=True).start()

    def stop_detection(self):
        self.detecting = False
        self.update_log("[INFO] Detection stopped.", "#ffcc00")
        self.status_bar.config(text="Status: Stopped", fg="#ffcc00")

    def clear_logs(self):
        self.log_display.delete('1.0', tk.END)

    def export_logs(self):
        with open("logs.txt", "w") as file:
            file.write(self.log_display.get('1.0', tk.END))
        self.update_log("[INFO] Logs exported to logs.txt", "#00cc66")

    ### ✅ CPU & Memory Usage Detection
    def detect_resource_usage(self):
        while self.detecting:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent

            if cpu_usage > 80:
                self.update_log(f"[ALERT] High CPU usage detected: {cpu_usage}%", "#ff3333")
                winsound.Beep(1000, 500)

            if memory_usage > 80:
                self.update_log(f"[ALERT] High memory usage detected: {memory_usage}%", "#ff3333")
                winsound.Beep(1000, 500)

            time.sleep(1)

    ### ✅ Mouse Activity Detection
    def on_click(self, x, y, button, pressed):
        if pressed:
            self.click_times.append(time.time())
            self.click_times = self.click_times[-10:]

            if len(self.click_times) >= 5 and self.click_times[-1] - self.click_times[-5] < 1:
                self.update_log("[ALERT] Suspicious rapid mouse clicks detected!", "#ff3333")
                winsound.Beep(1000, 500)

    def detect_mouse_activity(self):
        with mouse.Listener(on_click=self.on_click) as listener:
            listener.join()

    ### ✅ Network Change Detection
    def detect_network_change(self):
        while self.detecting:
            new_ips = {socket.gethostbyname(socket.gethostname())}
            if new_ips - self.known_ips:
                for ip in new_ips - self.known_ips:
                    self.update_log(f"[ALERT] New network connection detected: {ip}", "#ff3333")
                    winsound.Beep(1000, 500)

            self.known_ips = new_ips
            time.sleep(5)

    ### ✅ Failed Login Detection
    def detect_failed_logins(self):
        while self.detecting:
            output = subprocess.check_output(["powershell", "Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625}"], stderr=subprocess.DEVNULL).decode()
            if "4625" in output:
                self.update_log("[ALERT] Failed login attempt detected!", "#ff3333")
                winsound.Beep(1000, 500)
            time.sleep(10)

if __name__ == "__main__":
    app = AnomalyDetectionGUI()
    app.mainloop()
