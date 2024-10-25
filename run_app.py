import os
import subprocess
import threading
import webview

# Function to run the Django server
def run_django():
    os.chdir('E:/Arjun/Antivirusproject')
    subprocess.Popen(['python', 'manage.py', 'runserver'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

# JavaScript to add navigation controls
js_navigation_controls = """
const navDiv = document.createElement('div');
navDiv.style.position = 'fixed';
navDiv.style.top = '10px';
navDiv.style.right = '10px';
navDiv.style.zIndex = '1000';
navDiv.style.display = 'flex';
navDiv.style.gap = '10px';

// Back button
const backBtn = document.createElement('button');
backBtn.innerText = '⟵';
backBtn.onclick = () => history.back();
navDiv.appendChild(backBtn);

// Forward button
const forwardBtn = document.createElement('button');
forwardBtn.innerText = '⟶';
forwardBtn.onclick = () => history.forward();
navDiv.appendChild(forwardBtn);

// Refresh button
const refreshBtn = document.createElement('button');
refreshBtn.innerText = '⟳';
refreshBtn.onclick = () => location.reload();
navDiv.appendChild(refreshBtn);

document.body.appendChild(navDiv);
"""

def open_webview():
    # Create a webview window and inject JavaScript for navigation controls
    window = webview.create_window('Antivirus Dashboard', 'http://127.0.0.1:8000/')
    window.events.loaded += lambda: window.evaluate_js(js_navigation_controls)
    webview.start()

if __name__ == "__main__":
    threading.Thread(target=run_django, daemon=True).start()
    open_webview()
