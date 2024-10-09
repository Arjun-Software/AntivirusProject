import psutil
import platform
from datetime import datetime

def get_system_info():
    """Fetch system statistics like CPU, memory, disk usage, etc."""
    system_info = {}
    
    # CPU information
    system_info['cpu_percent'] = psutil.cpu_percent(interval=1)
    
    # Memory information
    mem = psutil.virtual_memory()
    system_info['total_memory'] = mem.total
    system_info['used_memory'] = mem.used
    system_info['memory_percent'] = mem.percent
    
    # Disk usage
    disk = psutil.disk_usage('/')
    system_info['total_disk'] = disk.total
    system_info['used_disk'] = disk.used
    system_info['disk_percent'] = disk.percent
    
    # Boot time
    boot_time_timestamp = psutil.boot_time()
    bt = datetime.fromtimestamp(boot_time_timestamp)
    system_info['boot_time'] = bt.strftime("%Y-%m-%d %H:%M:%S")
    
    # OS and platform information
    system_info['platform'] = platform.system()
    system_info['platform_release'] = platform.release()
    system_info['platform_version'] = platform.version()
    
    return system_info