import tkinter as tk
from tkinter import scrolledtext
from flask import Flask, request, render_template_string
import threading
import time
import psutil
from pynput import mouse

# Flask app setup
app = Flask(__name__)

# Failed login tracking
failed_logins = []
MAX_FAILED_ATTEMPTS = 5
TIME_FRAME = 60  # 60 seconds

class AnomalyDetectionGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("Anomaly Detection System")
        self.geometry("600x400")
        self.configure(bg="#1e1e1e")

        # Title Label
        tk.Label(self, text="Anomaly Detection System", font=("Arial", 18, "bold"), fg="#ffcc00", bg="#1e1e1e").pack(pady=10)

        # Log Display
        self.log_display = scrolledtext.ScrolledText(self, width=70, height=15, bg="#252526", fg="#ffffff", font=("Arial", 10))
        self.log_display.pack(pady=10)

        # Start Button
        self.start_btn = tk.Button(self, text="Start", bg="#00cc66", fg="#ffffff", command=self.start_detection)
        self.start_btn.pack(pady=5)

        # Stop Button
        self.stop_btn = tk.Button(self, text="Stop", bg="#cc0000", fg="#ffffff", command=self.stop_detection)
        self.stop_btn.pack(pady=5)

        self.detecting = False

    def start_detection(self):
        self.detecting = True
        self.update_log("Detection started...")
        threading.Thread(target=self.detect_resource_usage, daemon=True).start()
        threading.Thread(target=self.detect_mouse_activity, daemon=True).start()
        threading.Thread(target=self.detect_failed_logins, daemon=True).start()

    def stop_detection(self):
        self.detecting = False
        self.update_log("Detection stopped...")

    def update_log(self, message):
        self.log_display.insert(tk.END, message + "\n")
        self.log_display.yview(tk.END)

    def detect_resource_usage(self):
        while self.detecting:
            cpu_usage = psutil.cpu_percent(interval=1)
            memory_usage = psutil.virtual_memory().percent
            if cpu_usage > 80:
                self.update_log(f"[ALERT] High CPU usage detected: {cpu_usage}%")
            if memory_usage > 80:
                self.update_log(f"[ALERT] High memory usage detected: {memory_usage}%")
            time.sleep(1)

    click_times = []
    def on_click(self, x, y, button, pressed):
        if pressed:
            self.click_times.append(time.time())
            self.click_times = self.click_times[-10:]

            if len(self.click_times) >= 5 and self.click_times[-1] - self.click_times[-5] < 1:
                self.update_log("[ALERT] Suspicious rapid mouse clicks detected!")

    def detect_mouse_activity(self):
        with mouse.Listener(on_click=self.on_click) as listener:
            listener.join()

    def detect_failed_logins(self):
        global failed_logins
        while self.detecting:
            # Remove old login attempts outside the time frame
            now = time.time()
            failed_logins = [t for t in failed_logins if now - t < TIME_FRAME]

            if len(failed_logins) > MAX_FAILED_ATTEMPTS:
                self.update_log(f"[ALERT] Multiple failed login attempts detected! ({len(failed_logins)} in {TIME_FRAME} seconds)")
                failed_logins = []  # Reset after alert
            time.sleep(2)

# Flask route to serve login page
@app.route('/', methods=['GET', 'POST'])
def login():
    global failed_logins
    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        if username == 'admin' and password == 'password123':
            return "<h1>Login Successful!</h1>"
        else:
            failed_logins.append(time.time())
            return "<h1>Login Failed!</h1>"

    # HTML for login page
    html = """
    <!DOCTYPE html>
    <html>
    <head>
        <title>Login Page</title>
        <style>
            body { font-family: Arial, sans-serif; background-color: #1e1e1e; color: #ffffff; text-align: center; }
            form { margin-top: 50px; }
            input { margin: 10px; padding: 8px; width: 80%; max-width: 300px; }
            button { padding: 8px 20px; background-color: #00cc66; color: white; border: none; cursor: pointer; }
            button:hover { background-color: #00994d; }
        </style>
    </head>
    <body>
        <h2>Login Page</h2>
        <form method="post">
            <input type="text" name="username" placeholder="Username" required><br>
            <input type="password" name="password" placeholder="Password" required><br>
            <button type="submit">Login</button>
        </form>
    </body>
    </html>
    """
    return render_template_string(html)

# Start the Flask app in a separate thread
def run_flask():
    app.run(port=5000)

# Start Flask and GUI together
if __name__ == "__main__":
    threading.Thread(target=run_flask, daemon=True).start()
    gui = AnomalyDetectionGUI()
    gui.mainloop()
