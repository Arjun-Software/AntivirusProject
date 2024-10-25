from django.urls import path
from . import views
urlpatterns = [
    path('', views.index, name='index'),
    # path('index/', views.index, name='index'),  # Web interface route
    
    path('scan-file/', views.scan_file, name='scan_file'),
    path('adminLoginAPI/', views.adminLoginAPI.as_view() , name='adminLoginAPI'),
    path('scanUrlAPI/', views.scanUrlAPI.as_view() , name='scanUrlAPI'),
    path('filescanAPI/', views.filescanAPI.as_view() , name='filescanAPI'),
    path('demofilescanAPI/', views.demofilescanAPI.as_view() , name='demofilescanAPI'),
    path('scanningbwoserurl/', views.scanningbwoserurl.as_view() , name='scanningbwoserurl'),
    path('scan-system-files/', views.scan_system_files, name='scan_system_files'),
    path('disk-scanner/', views.disk_scanner_view, name='usb_scanner'),
    path('scan_disk/', views.scan_disk, name='scan_disk'),
    path('scan-url/', views.scan_urlbrowser, name='scan_urlbrowser'),
    path('get-report/', views.get_scan_report, name='get_report'),
    path('download/<str:file_name>/', views.FileDownloadView.as_view(), name='download_file'),
    path('ScanHandler/', views.ScanHandler, name='ScanHandler'),
    path('qurantineAPI/', views.qurantineAPI.as_view() , name='qurantineAPI'),
    path('Diskfrigmentation/', views.Diskfrigmentation.as_view() , name='Diskfrigmentation'),
    path('Diskcleanup/', views.Diskcleanup.as_view() , name='Diskcleanup'),
    path('powersaverAPI/', views.powersaverAPI.as_view() , name='powersaverAPI'),
    path('gamespeedAPI/', views.gamespeedAPI.as_view() , name='gamespeedAPI'),
    path('getIPaddressAPI/', views.getIPaddressAPI.as_view() , name='getIPaddressAPI'),
    path('system-status/', views.system_status, name='system_status'),
    path('check_url/', views.check_url, name='check_url'),  # API route
    path('api/check_file/',views.check_file_safety, name='check_file_safety'),
    path('USBscanner/', views.USBscanner, name='USBscanner'),
    path('get_install_app/', views.get_install_app.as_view(), name='get_install_app'),
    path('filescan/', views.file_scan_and_quarantine, name='file_scan_and_quarantine'),
    path('quarantine/list/', views.list_quarantined_files, name='list_quarantined_files'),
    path('quarantine/manage/', views.manage_quarantined_file, name='manage_quarantined_file'),
    path('firewall/', views.configure_firewall, name='configure_firewall'),
    path('defenderscan_file/', views.defenderscan_file, name='defenderscan_file'),
    path('DefenderAPI/', views.DefenderAPI.as_view(), name='defender_actions'),
    path('scan_results_view/', views.scan_results_view, name='scan_results_view'),
]

''' 
module.exports = {
  apps : [{
    name: 'Antivirus',
    script: 'manage.py',
    args: 'runserver 0.0.0.0:20001',
    instances: 1,
    autorestart: true,
    exp_backoff_restart_delay: 100,
    watch: false,
    max_memory_restart: '1G',
    interpreter:'/usr/bin/python3'
  }]
};

ecosystem.config.js

'''

