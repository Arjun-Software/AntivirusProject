import os
import subprocess
import threading
import webview
from django.core.management import execute_from_command_line
BASE_DIR = os.path.dirname(os.path.abspath(__file__))

def start_server():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Antivirusproject.settings')
    execute_from_command_line(['manage.py', 'runserver', '--noreload'])




js_navigation_controls = """
// Insert enhanced JavaScript for navigation
const headerDiv = document.createElement('div');
headerDiv.style.position = 'fixed';
headerDiv.style.top = '0';
headerDiv.style.right = '0';
headerDiv.style.width = '100%';
headerDiv.style.backgroundColor = '#333';
headerDiv.style.color = '#fff';
headerDiv.style.padding = '10px 20px';
headerDiv.style.display = 'flex';
headerDiv.style.justifyContent = 'space-between';
headerDiv.style.alignItems = 'center';
headerDiv.style.boxShadow = '0 4px 6px rgba(0, 0, 0, 0.1)';
headerDiv.style.zIndex = '1000';

const titleDiv = document.createElement('div');
titleDiv.innerText = 'Antivirus Dashboard';
titleDiv.style.fontSize = '18px';
headerDiv.appendChild(titleDiv);

const navControls = document.createElement('div');
navControls.style.display = 'flex';
navControls.style.gap = '10px';

const backBtn = document.createElement('button');
backBtn.innerText = '⟵';
backBtn.onclick = () => history.back();
styleButton(backBtn);
navControls.appendChild(backBtn);

const forwardBtn = document.createElement('button');
forwardBtn.innerText = '⟶';
forwardBtn.onclick = () => history.forward();
styleButton(forwardBtn);
navControls.appendChild(forwardBtn);

const refreshBtn = document.createElement('button');
refreshBtn.innerText = '⟳';
refreshBtn.onclick = () => location.reload();
styleButton(refreshBtn);
navControls.appendChild(refreshBtn);

headerDiv.appendChild(navControls);
document.body.style.paddingTop = '60px';
document.body.appendChild(headerDiv);

function styleButton(button) {
    button.style.backgroundColor = '#555';
    button.style.color = '#fff';
    button.style.border = 'none';
    button.style.padding = '8px 12px';
    button.style.borderRadius = '4px';
    button.style.cursor = 'pointer';
    button.style.fontSize = '14px';
    button.onmouseover = () => (button.style.backgroundColor = '#777');
    button.onmouseout = () => (button.style.backgroundColor = '#555');
}
"""

def open_webview():
    window = webview.create_window('Antivirus Dashboard', 'http://127.0.0.1:8000/',width=1200,  height=600, resizable=False  ) 
    window.events.loaded += lambda: window.evaluate_js(js_navigation_controls)
    webview.start()

if __name__ == "__main__":
    threading.Thread(target=start_server, daemon=True).start()
    open_webview()
