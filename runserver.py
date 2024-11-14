import os
import subprocess
import sys
import threading
from django.core.management import execute_from_command_line
import webview

def install_packages():
    """Install packages listed in requirements.txt if it exists."""
    req_file_path = os.path.join(os.path.dirname(__file__), 'requirements.txt')
    if os.path.exists(req_file_path):
        try:
            subprocess.check_call([sys.executable, '-m', 'pip', 'install', '-r', req_file_path])
        except Exception as e:
            print(f"Error installing packages: {e}")

def start_server():
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'Antivirusproject.settings')
    execute_from_command_line(['manage.py', 'runserver', '--noreload'])

install_packages()


server_thread = threading.Thread(target=start_server)
server_thread.start()

webview.create_window("Antivirus Dashboard")
webview.start()
