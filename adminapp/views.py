from pyexpat.errors import messages
import subprocess
import tempfile
from tkinter import Tk, filedialog
from django.shortcuts import render
from django.http import JsonResponse
import psutil
from rest_framework.views import APIView
import requests
import os
import datetime
import hashlib
from Antivirusproject.settings import VIRUSTOTAL_API_KEY ,poweBIdb
from .models import BlockedProgram
import os
import shutil
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
from .virustotal import scan_file_with_virustotal
from django.conf import settings
import win32api
import base64
import json
from django.core.files.storage import default_storage
QUARANTINE_DIR = settings.QUARANTINE_DIR
# Create your views here.



def response_messages(response_message, response_data,response_status):
    
    final_response_message = {
        "status":response_status,
        "message": response_message,
        "result": response_data,
        
    }
    return final_response_message


AUTH_SERVER = "http://142.93.247.109:10002/"
def dectoken(token):
    auth_server_response = requests.get(AUTH_SERVER+"Authapp/decrypt/?id="+ token, verify=False)
    gettoken = auth_server_response.json()                  
    if gettoken.get('data'):
        userid = gettoken['data']['userId']
        return userid
    else:
        None 



class adminLoginAPI(APIView):
    def post(self, request):
        try:
            login_data=request.data
            e = datetime.datetime.now()
            today = datetime.date.today() 
            IS_AUTH_SERVER = 1
            usersDB = admindb.superadmin.count_documents({'email': login_data['email'], 'password': login_data['password']}) 
            if usersDB > 0:
                usersDB = admindb.superadmin.find({'email': login_data['email'], 'password': login_data['password']}) 
                for user in usersDB:
                    if IS_AUTH_SERVER == 1 or IS_AUTH_SERVER == "1":
                        json_data = {
                            "userId": str(user['_id']),
                            "userType": "admin",
                            "multiLogin": "true",
                            "AllowedMax": "5",
                            "immediateRevoke": "false",
                            "metaData": {},
                            "Unique": str(today) + str(e.hour)+ str(e.minute) + str(e.second),
                            "accessTTL": "48h",
                            "refreshTTL": "180h"
                        }
                        auth_server_response = requests.post(
                            AUTH_SERVER+"Authapp/AccessToken2API/", json=json_data, verify=False)
                        print(auth_server_response.json())
                        token= auth_server_response.json()['data']
                        message = {
                            "message": "Login Successfully",
                            "token": token,
                            "userId": str(user['_id']),
                            "email":str(user['email']),
                            "status":"1",
                            "LoginType":"superadmin",
                        }
                        success_message = response_messages("success", message,200)
                        return JsonResponse(success_message, safe=False, status=200)
            else:
                message = {
                    "message":"invalid username or password",
                }
                success_message = response_messages("sucess",message,200)
                return JsonResponse(success_message, safe=False, status=404)
        except Exception as e:
            message =  {
                    "message": "Internal Server Error {}".format(e)
                }
            error_message = response_messages("failed", message,500)
            return JsonResponse(error_message, safe=False, status=500)

class browserAPI(APIView):
    def get(self,request):
        return render(request,'Antivirus/inner13.html')
class qurantineAPI(APIView):
    def get(self,request):
        return render(request,'Antivirus/qurantine.html')
    
def scan_page(request):
    return render(request, 'Antivirus/scan_page.html')

class Diskcleanup(APIView):
    def get(self,request):
        drives = []
        for partition in psutil.disk_partitions():
            if os.name == 'nt' and 'cdrom' not in partition.opts:  # Windows-specific check
                usage = psutil.disk_usage(partition.mountpoint)
                used_percentage = ((usage.total - usage.free) / usage.total) * 100
                
                # Extract the drive letter without backslashes
                drive_letter = os.path.splitdrive(partition.device)[0]
                print("----drive_letter----",drive_letter)
                drives.append({
                    'drive': drive_letter,
                    'total': usage.total // (1024 ** 3),  # Convert to GB
                    'free': usage.free // (1024 ** 3),    # Convert to GB
                    'used_percentage': used_percentage    # Pass used percentage to template
                })
        return render(request ,'Antivirus/diskcsuggestion.html', {'drives': drives})

@csrf_exempt
def delete_files(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        files = data.get('files', [])

        deleted_files = []
        errors = []

        for file_path in files:
            try:
                os.remove(file_path)  # Attempt to delete the file
                deleted_files.append(file_path)
            except PermissionError:
                errors.append(f"Permission denied: {file_path}")
            except FileNotFoundError:
                errors.append(f"File not found: {file_path}")
            except Exception as e:
                errors.append(f"Error deleting {file_path}: {str(e)}")

        return JsonResponse({
            'deleted_files': deleted_files,
            'errors': errors
        })
    return JsonResponse({'error': 'Invalid request method'}, status=400)


def get_available_drives(request):
    # Get list of available drives
    drives = win32api.GetLogicalDriveStrings()
    print("=========",drives)
    drive_list = [drive for drive in drives.split('\\') if drive]  # List of drives like ['C:\\', 'D:\\']
    print("--------",drive_list)
    return JsonResponse({'drives': drive_list})

def scan_drive_for_cleanup(request, drive):
    suggestions = []
    # Function to scan the selected drive for large files
    def scan_drive(drive):
        if os.path.exists(drive):
            for root, dirs, files in os.walk(drive):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    # Suggest files larger than 100 MB
                    if file_size > 100 * 1024 * 1024:  # 100 MB
                        print("-------file_path",file_path)
                        suggestions.append({
                            'file_path': file_path,
                            'size_mb': file_size / (1024 * 1024),  # Size in MB
                        })
    # Scan the selected drive
    scan_drive(drive)
    print("======suggestions======",suggestions)
    return JsonResponse({'suggestions': suggestions})

def suggest_cleanup(request):
    # Specify the drives you want to scan
    drives = ['C:\\', 'D:\\','E:\\','F:\\']  # Add more drives as needed
    suggestions = []

    # Function to scan a drive for large files
    def scan_drive(drive):
        if os.path.exists(drive):
            for root, dirs, files in os.walk(drive):
                for file in files:
                    file_path = os.path.join(root, file)
                    file_size = os.path.getsize(file_path)
                    # Suggest files larger than 100 MB
                    if file_size > 100 * 1024 * 1024:  # 100 MB
                        suggestions.append({
                            'file_path': file_path,
                            'size_mb': file_size / (1024 * 1024),  # Size in MB
                        })

    # Scan specified drives
    for drive in drives:
        scan_drive(drive)

    return JsonResponse({'suggestions': suggestions})
# def suggest_cleanup(request):
#     # Paths to scan for cleanup
#     user_temp_dir = os.path.join(os.environ['TEMP'])  # User's Temp directory
#     system_temp_dir = r'C:\Windows\Temp'  # System Temp directory
#     recycle_bin = r'C:\$Recycle.Bin'  # Recycle Bin path

#     suggestions = []

#     # Function to scan a directory for large files
#     def scan_directory(directory):
#         if os.path.exists(directory):
#             for root, dirs, files in os.walk(directory):
#                 for file in files:
#                     file_path = os.path.join(root, file)
#                     file_size = os.path.getsize(file_path)
#                     # Suggest files larger than 1 MB
#                     if file_size > 1024 * 1024:
#                         suggestions.append({
#                             'file_path': file_path,
#                             'size_mb': file_size / (1024 * 1024),  # Size in MB
#                         })

#     # Scan specified directories
#     scan_directory(user_temp_dir)
#     scan_directory(system_temp_dir)
#     scan_directory(recycle_bin)

#     return JsonResponse({'suggestions': suggestions})

class powersaverAPI(APIView):
    def get(self,request):
        return render(request,'Antivirus/inner4.html')

API_KEY = '671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850'
class scanUrlAPI(APIView):#this is done
    def get(self,request):
        return  render(request,"Antivirus/urlscan.html")
    def post(self, request):
        try:
            url = request.POST.get('url')
            print("====", url)
            geturl = url.replace("https://", "").rstrip("/")
            url = "https://www.virustotal.com/api/v3/domains/" + geturl
            headers = {
                "accept": "application/json",
                "x-apikey": API_KEY
            }
            response = requests.get(url, headers=headers)
            response_data = response.json()
            print("*-*-rsd*-",response_data)
            # Prepare a formatted response for the template
            if 'data' in response_data:
                formatted_response = {
                    'id': response_data['data']['id'],
                    'type': response_data['data']['type'],
                    'registrar': response_data['data']['attributes']['registrar'],
                    'creation_date': response_data['data']['attributes']['creation_date'],
                    'last_https_certificate_date': response_data['data']['attributes']['last_https_certificate_date'],
                    'last_analysis_results': response_data['data']['attributes']['last_analysis_results'],
                    
                    'popularity_ranks': {
                        'statvoo_rank': response_data['data']['attributes']['popularity_ranks'],
                        'alexa_rank': response_data['data']['attributes']['popularity_ranks'].get('alexa_rank', 'N/A')  # handle missing data
                    }
                }
                print("---res------",formatted_response)
            else:
                pass
            
            return render(request, "Antivirus/urlscan.html", {'response': formatted_response})
        except Exception as e:
            message = {
                "message": "Internal Server Error {}".format(e)
            }
            error_message = response_messages("failed", message, 500)
            return JsonResponse(error_message, safe=False, status=500)

         

class testfilescanAPI(APIView):
    def post(self,request):
        try:
            data =  request.data
            getfile = data['file']
            # print("=====",getfile)
            header,get_name = getfile.split(';base64,')
            get_name =header.split('name=')[1]
            print("=-get_name ----",get_name)
            getfile = base64.b64decode(getfile)
            with open(get_name, 'wb') as f:
                f.write(getfile)
            # print("----",getfile)
            fileurl  = "https://www.virustotal.com/api/v3/files"
            files = { "file": (get_name, open(get_name, "rb"), "text/x-python") }
            # print("*******",files)
            headers = {
            "accept": "application/json",
            "x-apikey": "671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850"
            }
            response = requests.post(fileurl, files=files, headers=headers)
            response = response.json()
            id = response['data']['id']
            print("----",response['data']['id'])
            re = "https://www.virustotal.com/api/v3/files/"+"NTI4MTA1ZjU1MmQzZWVmODMxMmMwY2Q1ZGViODAzMWY6MTcyNzE4NjU1Nw=="#"https://www.virustotal.com/api/v3/files/"+id
            re = requests.get(re, headers=headers)
            # print("----------------",re.json())
            success_message = response_messages("success", response,200)
            return JsonResponse(success_message, safe=False, status=200)
        except Exception as e:
            message =  {
                    "message": "Internal Server Error {}".format(e)
                }
            error_message = response_messages("failed", message,500)
            return JsonResponse(error_message, safe=False, status=500)

class filescanAPI(APIView):
    def get(self, request):
        return render(request, 'Antivirus/filescan.html')

    def post(self, request):
        try:
            uploaded_file = request.FILES['file']
            files = {'file': (uploaded_file.name, uploaded_file.read())}
            params = {'apikey': API_KEY}

            # Send file to the scanning API
            file_scan_response = requests.post(FILE_SCAN_API, files=files, data=params)

            if file_scan_response.status_code == 200:
                scan_id = file_scan_response.json().get('scan_id')

                # Fetch scan report using the scan_id
                report_params = {'apikey': API_KEY, 'resource': scan_id}
                report_response = requests.get(FILE_REPORT_API, params=report_params)
                report_json = report_response.json()

                # Extract relevant data for each antivirus vendor
                scan_results = report_json.get('scans', {})

                # Format data for rendering
                scan_data = [
                    {
                        'vendor': vendor,
                        'result': details.get('result', 'Undetected'),
                        'status': 'Undetected' if details.get('detected') is False else 'Detected'
                    }
                    for vendor, details in scan_results.items()
                ]

                context = {
                    'scan_data': scan_data,
                    'file_info': {
                        'file_name': uploaded_file.name,
                        'size': uploaded_file.size,
                        'scan_date': report_json.get('scan_date')
                    }
                }
                print("----209----",context['file_info'])
                # Render response in the template
                return render(request, 'Antivirus/filescanningresult.html', context)

            else:
                return JsonResponse({'error': 'Unable to scan file'}, status=500)

        except KeyError:
            return JsonResponse({'error': 'Invalid data'}, status=400)

        except ValueError as e:
            return JsonResponse({'error': f'Failed to decode JSON response: {str(e)}'}, status=500)


# class filescanAPI(APIView):
#     def get(self,request):
#         return render(request, 'Antivirus/filescan.html')
#     def post(self,request):
#         try:
#             uploaded_file = request.FILES['file']
#             files = {'file': (uploaded_file.name, uploaded_file.read())}
#             params = {'apikey': API_KEY}

#             file_scan_response = requests.post(FILE_SCAN_API, files=files, data=params)
#             if file_scan_response.status_code == 200:
#                 print("======",file_scan_response.json()  , "-----",file_scan_response.status_code )
#                 scan_id = file_scan_response.json().get('scan_id')
#                 report_params = {'apikey': API_KEY, 'resource': scan_id}
#                 print("--scan_id----",scan_id)
#                 report_params = {'apikey': API_KEY, 'resource': scan_id}
#                 report_response = requests.get(FILE_REPORT_API, params=report_params)
#                 report_response = report_response.json()
#                 # Debug: Print the report response text
#                 print("Report Response Text:", report_response['scans'])
#                 # Attempt to decode the JSON
#                 return JsonResponse(report_response['scans'])
#             else:
#                 return JsonResponse({'error': 'Unable to scan file'}, status=500)
#         except KeyError:
#             return JsonResponse({'error': 'Invalid data'}, status=400)
#         except ValueError as e:
#             return JsonResponse({'error': 'Failed to decode JSON response: ' + str(e)}, status=500)





class demofilescanAPI(APIView):
    def post(self, request):
        try:
            data = request.data
            getfile = data['file']
            
            # Check if file exists
            if not os.path.exists(getfile):
                return JsonResponse({"message": "File not found."}, status=400)

            fileurl = "https://www.virustotal.com/api/v3/files"
            files = {"file": open(getfile, "rb")}
            headers = {
                "accept": "application/json",
                "x-apikey": "671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850"  # Replace with your API key
            }

            # Upload file
            response = requests.post(fileurl, files=files, headers=headers)
            response_json = response.json()

            # Check for successful response
            if response.status_code != 200 or 'data' not in response_json:
                return JsonResponse({"message": response_json.get("error", "Unknown error")}, status=response.status_code)

            id = response_json['data']['id']
            print("----", id)
            file_info_url = f"https://www.virustotal.com/api/v3/files/{id}"
            file_info_response = requests.get(file_info_url, headers=headers)

            # Check for successful response
            if file_info_response.status_code != 200:
                return JsonResponse({"message": file_info_response.json().get("error", "Unknown error")}, status=file_info_response.status_code)

            # print("----------------", file_info_response.json())
            success_message = response_messages("success", response_json, 200)
            return JsonResponse(success_message, safe=False, status=200)
        
        except Exception as e:
            message = {
                "message": "Internal Server Error {}".format(e)
            }
            error_message = response_messages("failed", message, 500)
            return JsonResponse(error_message, safe=False, status=500)

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = '671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'
import time
class scanningbwoserurl(APIView):
    def get(self,request):
        url = request.GET.get('url')
        params = {'apikey': API_KEY, 'url': url}
        response = requests.post(SCAN_URL, data=params)
        
        if response.status_code == 200:
            json_response = response.json()
            scan_id = json_response.get('scan_id')
            print(f"Scan ID: {scan_id}")
            # return scan_id
        
            params = {'apikey': API_KEY, 'resource': scan_id}
            while True:
                response = requests.get(REPORT_URL, params=params)
                
                if response.status_code == 200:
                    json_response = response.json()
                    if json_response.get('response_code') == 1:
                        print("----",json_response)
                        success_message = response_messages("sucess",json_response,404)
                        return JsonResponse(success_message, safe=False, status=404)
                    else:
                        print("Waiting for report to be generated...")
                        time.sleep(10)  # Wait for 10 seconds before retrying
                else:
                    message = {
                    "message":f"Error fetching scan report: {response.status_code}"
                    }
                    success_message = response_messages("sucess",message,404)
                    return JsonResponse(success_message, safe=False, status=404)
        else:
            message = {
            "message":f"Error fetching scan report: {response.status_code}"
            }
            success_message = response_messages("sucess",message,404)
            return JsonResponse(success_message, safe=False, status=404)
    

    import requests


# API Endpoints
API_KEY = VIRUSTOTAL_API_KEY
URL_SCAN_API = 'https://www.virustotal.com/vtapi/v2/url/scan'
URL_REPORT_API = 'https://www.virustotal.com/vtapi/v2/url/report'
FILE_SCAN_API = 'https://www.virustotal.com/vtapi/v2/file/scan'
FILE_REPORT_API = 'https://www.virustotal.com/vtapi/v2/file/report'


def index(request):
    return render(request,'Antivirus/index.html')


def urlindex(request):
    """Handles URL and file scanning via the web interface."""
    context = {}

    if request.method == 'POST':
        # URL Scanning Logic
        if 'url' in request.POST:
            url = request.POST.get('url')
            params = {'apikey': API_KEY, 'url': url}
            
            scan_response = requests.post(URL_SCAN_API, data=params)
            if scan_response.status_code == 200:
                scan_id = scan_response.json().get('scan_id')
                report_params = {'apikey': API_KEY, 'resource': scan_id}
                report_response = requests.get(URL_REPORT_API, params=report_params)
                context['report'] = report_response.json()
                
            else:
                context['error'] = 'Unable to scan URL'

        # File Scanning Logic
        elif 'file' in request.FILES:
            uploaded_file = request.FILES['file']
            print("-----------",uploaded_file)
            files = {'file': (uploaded_file.name, uploaded_file.read())}
            params = {'apikey': API_KEY}
            
            file_scan_response = requests.post(FILE_SCAN_API, files=files, data=params)
            if file_scan_response.status_code == 200:
                scan_id = file_scan_response.json().get('scan_id')
                report_params = {'apikey': API_KEY, 'resource': scan_id}
                report_response = requests.get(FILE_REPORT_API, params=report_params)
                context['report'] = report_response.json()
            else:
                context['error'] = 'Unable to scan file'

    return render(request, 'filescanning.html', context)


@csrf_exempt
def scan_url(request):
    """API endpoint for scanning URLs via a POST request."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data['url']
            params = {'apikey': API_KEY, 'url': url}
            
            scan_response = requests.post(URL_SCAN_API, data=params)
            if scan_response.status_code == 200:
                scan_id = scan_response.json().get('scan_id')
                report_params = {'apikey': API_KEY, 'resource': scan_id}
                report_response = requests.get(URL_REPORT_API, params=report_params)
                return JsonResponse(report_response.json())
            else:
                return JsonResponse({'error': 'Unable to scan URL'}, status=500)
        except KeyError:
            return JsonResponse({'error': 'Invalid data'}, status=400)
    return JsonResponse({'message': 'Only POST requests allowed'}, status=405)


API_KEY = "d575429ebf5c1d1391beb54656d3d6bdf5c78e237071b1ca13fcda48002291ed"

@csrf_exempt
# def scan_file(request):
#     """API endpoint for scanning files via a POST request."""
#     if request.method == 'POST':
#         try:
#             uploaded_file = request.FILES['file']
#             files = {'file': (uploaded_file.name, uploaded_file.read())}
#             params = {'apikey': API_KEY}
#             print("=======",files)
#             file_scan_response = requests.post(FILE_SCAN_API, files=files, data=params)
#             if file_scan_response.status_code == 200:
#                 scan_id = file_scan_response.json().get('scan_id')
#                 report_params = {'apikey': API_KEY, 'resource': scan_id}
#                 report_response = requests.get(FILE_REPORT_API, params=report_params)
#                 return JsonResponse(report_response.json())
#             else:
#                 return JsonResponse({'error': 'Unable to scan file'}, status=500)
#         except KeyError:
#             return JsonResponse({'error': 'Invalid data'}, status=400)
#     return JsonResponse({'message': 'Only POST requests allowed'}, status=405)


def scan_file(request):
    """API endpoint for scanning files via a POST request."""
    if request.method == 'POST':
        try:
            uploaded_file = request.FILES['file']
            files = {'file': (uploaded_file.name, uploaded_file.read())}
            params = {'apikey': API_KEY}

            file_scan_response = requests.post(FILE_SCAN_API, files=files, data=params)
            if file_scan_response.status_code == 200:
                print("======",file_scan_response.json()  , "-----",file_scan_response.status_code )
                scan_id = file_scan_response.json().get('scan_id')
                report_params = {'apikey': API_KEY, 'resource': scan_id}
                print("--scan_id----",scan_id)
                report_params = {'apikey': API_KEY, 'resource': scan_id}
                report_response = requests.get(FILE_REPORT_API, params=report_params)
                report_response = report_response.json()
                # Debug: Print the report response text
                print("Report Response Text:", report_response)
                # Attempt to decode the JSON
                return JsonResponse(report_response)
            else:
                return JsonResponse({'error': 'Unable to scan file'}, status=500)
        except KeyError:
            return JsonResponse({'error': 'Invalid data'}, status=400)
        except ValueError as e:
            return JsonResponse({'error': 'Failed to decode JSON response: ' + str(e)}, status=500)
    return JsonResponse({'message': 'Only POST requests allowed'}, status=405)




# urlscanner/views.py

API_KEY = VIRUSTOTAL_API_KEY
FILE_SCAN_API = 'https://www.virustotal.com/vtapi/v2/file/scan'
FILE_REPORT_API = 'https://www.virustotal.com/vtapi/v2/file/report'

def scan_all_files(directory):
    """Scan all files in a specified directory."""
    results = []
    for root, dirs, files in os.walk(directory):
        for file in files:
            print("*****",file)
            file_path = os.path.join(root, file)
            with open(file_path, 'rb') as f:
                files = {'file': (file, f.read())}
                params = {'apikey': API_KEY}
                print("------",files)
                
                # Submit file for scanning
                response = requests.post(FILE_SCAN_API, files=files, data=params)
                if response.status_code == 200:
                    print("---response.json()----",response.json())
                    scan_id = response.json().get('scan_id')
                    report_params = {'apikey': API_KEY, 'resource': scan_id}
                    report_response = requests.get(FILE_REPORT_API, params=report_params)
                    results.append(report_response.json())
                else:
                    results.append({'error': f"Unable to scan {file}"})
    
    return results


@csrf_exempt
def scan_system_files(request):
    """API to trigger system-wide file scanning."""
    if request.method == 'POST':
        directory = request.POST.get('directory', '/')  # Default to root directory, be cautious!
        scan_results = scan_all_files(directory)
        return JsonResponse(scan_results, safe=False)
    
    return render(request,  'scan_all_files.html')


# usb scanner 

API_KEY = VIRUSTOTAL_API_KEY
FILE_SCAN_API = 'https://www.virustotal.com/vtapi/v2/file/scan'
FILE_REPORT_API = 'https://www.virustotal.com/vtapi/v2/file/report'

def list_disk_drives():
    """Return a list of connected disk drives (USB and other drives)."""
    drives = []
    if os.name == 'nt':  # Windows
        for drive in range(65, 91):  # A-Z drives
            drive_letter = f"{chr(drive)}:\\"
            if os.path.exists(drive_letter):
                drives.append(drive_letter)
    # Additional logic can be added here for Linux/Mac as needed
    return drives


def scan_disk_files(drive_path):
    """Scan all files in the disk drive."""
    for root, dirs, files in os.walk(drive_path):
        for file in files:
            file_path = os.path.join(root, file)
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
            
            # Skip files larger than 10 MB
            # if file_size_mb > 10:
            #     yield f"Skipping {file_path} (Size: {file_size_mb:.2f} MB - exceeds 10 MB limit)\n"
            #     continue

            yield f"Scanning {file_path}... Size: {file_size_mb:.2f})...\n"
            
            # Simulate scan (replace this with actual scan function)
            scan_result = {"status": "success", "file": file_path}
            if scan_result["status"] == "success":
                yield f"Scan completed for {file_path} -> Status: {scan_result['status']}\n"
            else:
                yield f"Error scanning {file_path}\n"

            time.sleep(1)  # Simulate delay between scans

@csrf_exempt
def scan_disk(request):
    """Start scanning the disk and stream results."""
    if request.method == 'POST':
        disk_drives = list_disk_drives()

        if not disk_drives:
            return StreamingHttpResponse("No disk drives detected.", content_type="text/plain")

        def scan_and_stream():
            for drive in disk_drives:
                yield f"Scanning drive: {drive}\n"
                yield from scan_disk_files(drive)
            yield "Disk scan completed.\n"

        return StreamingHttpResponse(scan_and_stream(), content_type="text/plain")

    return JsonResponse({'message': 'Only POST requests allowed'}, status=405)


def disk_scanner_view(request):
    """Render the USB scanner template."""
    return render(request, 'Antivirus/distscan.html')

#scan_urlbrowser

import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

API_KEY = VIRUSTOTAL_API_KEY
SCAN_URL_API = 'https://www.virustotal.com/vtapi/v2/url/scan'
REPORT_URL_API = 'https://www.virustotal.com/vtapi/v2/url/report'

@csrf_exempt
def scan_urlbrowser(request):
    """Submit a URL to VirusTotal for scanning."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url_to_scan = data.get('url')
            if not url_to_scan:
                return JsonResponse({'error': 'No URL provided'}, status=400)
            print("-------",url_to_scan)
            # Submit the URL for scanning
            params = {'apikey': API_KEY, 'url': url_to_scan}
            scan_response = requests.post(SCAN_URL_API, data=params)
            print("=====",scan_response)
            if scan_response.status_code == 200:
                scan_id = scan_response.json().get('scan_id')
                return JsonResponse({'scan_id': scan_id})
            else:
                return JsonResponse({'error': 'Unable to scan URL'}, status=500)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return render(request, 'browser.html')  #JsonResponse({'message': 'Only POST requests allowed'}, status=405)

@csrf_exempt
def get_scan_report(request):
    """Fetch the scan report for a previously scanned URL."""
    if request.method == 'POST':
        try:
            data = json.loads(request.body) 
            scan_id = data.get('scan_id')
            if not scan_id:
                return JsonResponse({'error': 'No scan ID provided'}, status=400)

            # Retrieve the scan report
            params = {'apikey': API_KEY, 'resource': scan_id}
            report_response = requests.get(REPORT_URL_API, params=params)

            if report_response.status_code == 200:
                report_data = report_response.json()
                return JsonResponse(report_data)
            else:
                return JsonResponse({'error': 'Unable to retrieve report'}, status=500)

        except Exception as e:
            return JsonResponse({'error': str(e)}, status=500)
    return JsonResponse({'message': 'Only POST requests allowed'}, status=405)






# your_app_name/views.py

import requests
from django.http import JsonResponse, HttpResponse
from django.views import View
import os

class FileDownloadView(View):
    def get(self, request, file_name):
        # Path to the file
        file_path = os.path.join('your_file_directory', file_name)

        # Check if the file exists
        if not os.path.exists(file_path):
            return JsonResponse({'error': 'File not found'}, status=404)

        # Scan the file after downloading
        scan_result = self.scan_file(file_path)
        
        # You may want to check the scan_result here and act accordingly
        if scan_result.get('malicious'):
            return JsonResponse({'error': 'File is malicious and cannot be downloaded'}, status=403)

        # Return the file response
        with open(file_path, 'rb') as f:
            response = HttpResponse(f.read(), content_type='application/octet-stream')
            response['Content-Disposition'] = f'attachment; filename={file_name}'
            return response

    def scan_file(self, file_path):
        # Example for VirusTotal API
        api_key = VIRUSTOTAL_API_KEY
        url = 'https://www.virustotal.com/api/v3/files'

        # Read the file
        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            headers = {
                'x-apikey': api_key,
            }
            
            response = requests.post(url, headers=headers, files=files)
            
            if response.status_code == 200:
                return response.json()
            else:
                return {'error': 'Failed to scan the file', 'details': response.json()}



# file_scanner.py

import os
import time
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler
import requests

class ScanHandler(FileSystemEventHandler):
    def on_created(self, event):
        # Check if the created event is a file
        if not event.is_directory:
            print(f"File downloaded: {event.src_path}")
            self.scan_file(event.src_path)

    def scan_file(self, file_path):
        # Example for VirusTotal API
        api_key = VIRUSTOTAL_API_KEY
        url = 'https://www.virustotal.com/api/v3/files'

        with open(file_path, 'rb') as f:
            files = {'file': (os.path.basename(file_path), f)}
            headers = {
                'x-apikey': api_key,
            }
            response = requests.post(url, headers=headers, files=files)
            
            if response.status_code == 200:
                scan_result = response.json()
                print(f"Scan result for {file_path}: {scan_result}")
                # You can add logic here to take action based on scan results
            else:
                print(f"Failed to scan the file: {response.json()}")

def start_monitoring(download_folder):
    event_handler = ScanHandler()
    observer = Observer()
    observer.schedule(event_handler, download_folder, recursive=False)
    observer.start()
    print(f"Monitoring {download_folder} for new downloads...")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        observer.stop()
    observer.join()

if __name__ == "__main__":
    download_folder = os.path.expanduser('~/Downloads')  # Change to your download folder path if necessary
    start_monitoring(download_folder)


# monitoring/views.py
from django.shortcuts import render
from .utils import get_system_info

def system_status(request):
    # Get system metrics
    system_info = get_system_info()
    
    # Render them in the template
    return render(request, 'Antivirus/system_status.html', {'system_info': system_info})





# views.py in your Django app

from django.http import JsonResponse
import requests
from django.views.decorators.csrf import csrf_exempt

# Example function to check URL safety using VirusTotal
def check_url_safety(url):
    url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
    headers = {
            "accept": "application/json",
            "x-apikey": VIRUSTOTAL_API_KEY
            }
    url = "https://www.virustotal.com/api/v3/urls/"+url_id
    response = requests.get(url, headers=headers)
    data = response.json()
    if 'data' not in data:
        print("===url result===",response.json())
        pass
    else:
        # data = data['data']['attributes']
        # print("===final==","url:-",url ,"result:-",data['data']['attributes']['last_analysis_stats'])
        return response.json()

# View to handle URL safety check API endpoint
@csrf_exempt
def check_url(request):
    if request.method == 'GET':
        url = request.GET.get('url')
        if url:
            result = check_url_safety(url)
            
            if result is not None:
                print("--825----",result['data']['attributes']['last_analysis_stats'])
                # print("---",result['malicious'])
                # Determine if the URL is flagged as malicious
                if 'malicious' in result and result['malicious']:
                    return JsonResponse({'is_malicious': True})
                else:
                    return JsonResponse({'is_malicious': False})
            else:
                return JsonResponse({'is_malicious': False})
        else:
            return JsonResponse({'error': 'No URL provided'}, status=400)
    else:
        return JsonResponse({'error': 'Invalid request method'}, status=405)


# --------------------
from django.http import JsonResponse
import requests
from django.http import JsonResponse


@csrf_exempt
def check_file_safety(request):
    file_url = request.GET.get('file_url')
    print("--file_url-",file_url)
    if not file_url:
        return JsonResponse({'error': 'No file URL provided.'}, status=400)

    # VirusTotal URL Report API (to check if the file exists in the database)
    vt_report_url = 'https://www.virustotal.com/vtapi/v2/url/report'
    params_report = {'apikey': VIRUSTOTAL_API_KEY, 'resource': file_url}
    response = requests.get(vt_report_url, params=params_report)
    response_data = response.json()
    if response_data['response_code'] == 1:  # URL was found and processed
        positives = response_data['positives']
        total_scans = response_data['total']

        if positives == 0:
            safety_message = "The file is safe and clean."
        else:
            safety_message = f"The file has been flagged as malicious by {positives} out of {total_scans} scanners."

        # You can also provide a link to the full VirusTotal report
        permalink = response_data.get('permalink')

        return JsonResponse({
            'is_safe': positives == 0,
            'message': safety_message,
            'permalink': permalink
        })
 
    else:
        return JsonResponse({
            'error': response_data.get('verbose_msg', 'Error scanning the file.')
        }, status=400)


class gamespeedAPI(APIView):
    def get(self,request):
        return render(request,'Antivirus/inner4.html')
    def post(self,request):
        try:
            game_file = request.FILES.get('file', None)
        
            if game_file:
                file_bytes = game_file.read()

                # Prepare the file for VirusTotal or your API
                files = {'file': (game_file.name, file_bytes)}

                # Assuming you are sending it to VirusTotal API
                response = requests.post(
                    'https://www.virustotal.com/api/v3/files',
                    headers={'x-apikey': VIRUSTOTAL_API_KEY},
                    files=files
                )
                scan_result = response.json()
                id = scan_result['data']['id']
                file_analysis = f"https://www.virustotal.com/api/v3/analyses/{id}"
                headers = {
                    "x-apikey": VIRUSTOTAL_API_KEY
                }
                response = requests.get(file_analysis, headers=headers)
                result = response.json()
                if result['data']['attributes']['status'] == 'completed':
                    final_result = result['data']['attributes']
                    result = {
                        "status":final_result['status'],
                        "stats":final_result["stats"]
                    }
                    success_message = response_messages("success", result,200)
                    return JsonResponse(success_message, safe=False, status=200)
                else:
                    message={"message": "file not scanning"}
                    success_message = response_messages("success", result['data']['attributes'],200)
                    return JsonResponse(success_message, safe=False, status=200)
        except Exception as e:
            message = {
                    "message": "Internal Server Error{}".format(e)
                }
            error_message = response_messages('failed', message, 500)
            return JsonResponse(error_message, safe=False, status=500)

#getIp
import socket
class getIPaddressAPI(APIView):
    def get(self,request):
        hostname = socket.gethostname()
    
        # Get the IP address of the machine
        ip_address = socket.gethostbyname(hostname)
        
        return JsonResponse({'ip': ip_address})
import ctypes
import sys
import os

# def is_admin():
#     try:
#         return ctypes.windll.shell32.IsUserAnAdmin()
#     except:
#         return False

# if not is_admin():
#     # Relaunch the script with admin privileges
#     ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
# else:
#     # Your defrag command here
#     os.system("defrag C: /U /V")

class Diskfrigmentation(APIView):
    def get(self, request):
        # Get list of drives and their sizes
        drives = []
        for partition in psutil.disk_partitions():
            if os.name == 'nt' and 'cdrom' not in partition.opts:  # Windows-specific check
                usage = psutil.disk_usage(partition.mountpoint)
                used_percentage = ((usage.total - usage.free) / usage.total) * 100
                
                # Extract the drive letter without backslashes
                drive_letter = os.path.splitdrive(partition.device)[0]
                print("----drive_letter----",drive_letter)
                drives.append({
                    'drive': drive_letter,
                    'total': usage.total // (1024 ** 3),  # Convert to GB
                    'free': usage.free // (1024 ** 3),    # Convert to GB
                    'used_percentage': used_percentage    # Pass used percentage to template
                })
        
        # Pass drive information to the template
        return render(request, 'Antivirus/inner2.html', {'drives': drives})
    def post(self, request):
        # Get the selected drive letter from the POST data
        drive_letter = request.POST.get('drive_letter') # Default to C: if no drive selected
        try:
            # For Windows OS
            print("-------",drive_letter)
            if os.name == 'nt':  # Check if the OS is Windows
                command = ['defrag', drive_letter, '/O', '/M']  # Defragment with optimization and multi-threading
                result = subprocess.run(command, check=True, capture_output=True, text=True)
                message = f"Disk defragmentation started for {drive_letter}. Output: {result.stdout}"
            else:
                # For Linux, as an example (this may vary based on the specific file system)
                command = ['e4defrag', f'/mnt/{drive_letter}']
                result = subprocess.run(command, check=True, capture_output=True, text=True)
                message = f"Disk defragmentation started for {drive_letter}. Output: {result.stdout}"
                
            return JsonResponse({'status': 'success', 'message': message})

        except subprocess.CalledProcessError as e:
            # Handle cases where the command fails
            return JsonResponse({'status': 'error', 'message': f"Error: {e.stderr.strip()}"})
        except Exception as e:
            # General exception handling
            return JsonResponse({'status': 'error', 'message': str(e)})
            
def defrag_disk():
    # System command for Windows
    subprocess.run(["defrag", "C:"], shell=True)




# Function to list files on a USB device
def list_usb_files():
    partitions = psutil.disk_partitions()
    usb_files = []
    
    for partition in partitions:
        if 'removable' in partition.opts:
            usb_root = partition.mountpoint
            for root, dirs, files in os.walk(usb_root):
                for file in files:
                    file_path = os.path.join(root, file)
                    usb_files.append(file_path)
                    
    return usb_files



def demoUSBscanner(request):
    if request.method == 'POST':
        usb_files = list_usb_files()
        print("*-*-*usb_files*-*-",usb_files)
        if not usb_files:
            print("No USB devices detected.")
            return
        for file_path in usb_files:
            file_size_mb = os.path.getsize(file_path) / (1024 * 1024) 
            if file_size_mb > 10:
                print(f"Skipping file: {file_path} (Size: {file_size_mb:.2f} MB - exceeds 100 MB limit)")
                continue
            print(f"Scanning ----- {file_path}...")
            scan_result = scan_file_with_virustotal(file_path)
        return JsonResponse(scan_result)
    
    return render(request, 'Antivirus/usb_scanner.html')



#===========
from django.http import StreamingHttpResponse
import time  # To simulate delay between scans for demonstration
def scan_file_with_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    print("-----",file_path)
    # Upload the file to VirusTotal
    with open(file_path, 'rb') as file:
        headers = {
            'x-apikey': VIRUSTOTAL_API_KEY
        }
        response = requests.post(url, headers=headers, files={'file': file})
        scan_result = response.json()
        id = scan_result['data']['id']
        file_analysis = f"https://www.virustotal.com/api/v3/analyses/{id}"
        headers = {
            "x-apikey": VIRUSTOTAL_API_KEY
        }
        response = requests.get(file_analysis, headers=headers)
        result = response.json()
        
        if 'data' in result:
            if  'status' in result['data']['attributes']:
                print("-----res---",result['data']['attributes']['status'])
                print("-----stats---",result['data']['attributes']['stats'])
            else:
                pass
        else:
            pass
    return result  # Return the response from VirusTotal

# Function to stream USB file scan results
@csrf_exempt
def USBscanner(request):
    if request.method == 'POST':
        usb_files = list_usb_files()
        if not usb_files:
            return StreamingHttpResponse("No USB devices detected.", content_type="text/plain")

        def scan_and_stream():
            for file_path in usb_files:
                file_size_mb = os.path.getsize(file_path) / (1024 * 1024)
                if file_size_mb > 10:
                    print(f"Skipping {file_path} (Size: {file_size_mb:.2f} MB - exceeds 10 MB limit)\n")
                    continue
                
                print(f"Scanning {file_path}...\n")
                scan_result = scan_file_with_virustotal(file_path)

                if 'data' in scan_result:
                    stats = scan_result['data']['attributes']['stats']
                    yield f"Scan completed for {file_path} -> Malicious: {stats['malicious']}, Undetected: {stats['undetected']}\n"
                else:
                    yield f"Error scanning {file_path}\n"

                time.sleep(1)  # Simulate delay

        return StreamingHttpResponse(scan_and_stream(), content_type="text/plain")

    return render(request, 'usb_scanner.html')

import subprocess
class get_install_app(APIView):
    def get(self, request):
        try:
            # Using the 'wmic' command to get installed apps
            output = subprocess.check_output('wmic product get name', shell=True)
            apps = output.decode('latin-1').splitlines()
            apps = [app.strip() for app in apps if app.strip()][1:]

            return render(request, "Antivirus/installed_apps.html", {'apps': apps})
        except Exception as e:
            return render(request, "Antivirus/installed_apps.html", {'apps': None})
        






@csrf_exempt
def list_quarantined_files(request):
    if request.method == 'GET':
        # List all files in the quarantine directory
        files = os.listdir(QUARANTINE_DIR)
        # Render the template and pass the list of quarantined files
        return render(request, 'Antivirus/qurantine.html', {'quarantined_files': files})

    return JsonResponse({'error': 'Invalid request method'}, status=400)

@csrf_exempt
def file_scan_and_quarantine(request):
    if request.method == 'POST':
        file = request.FILES.get('file')

        if not file:
            return JsonResponse({'error': 'No file provided'}, status=400)

        # Create a temporary file
        with tempfile.NamedTemporaryFile(delete=False) as temp_file:
            temp_file_path = temp_file.name  # Get the temporary file path

            # Write the uploaded file to the temporary file
            for chunk in file.chunks():
                temp_file.write(chunk)

        try:
            # Add your scanning logic here
            # e.g., scan the temp_file_path with VirusTotal or your own logic

            # Example logic for quarantine decision
            is_infected = False  # Replace with actual scanning logic

            if is_infected:
                # Move the file to quarantine directory
                quarantine_path = os.path.join(QUARANTINE_DIR, os.path.basename(temp_file_path))
                os.rename(temp_file_path, quarantine_path)  # Move to quarantine
                return JsonResponse({'message': 'File quarantined successfully.'})
            else:
                # Clean up the temporary file
                os.remove(temp_file_path)
                return JsonResponse({'message': 'File is clean.'})

        except Exception as e:
            # Ensure the temp file is deleted if there's an error
            if os.path.exists(temp_file_path):
                os.remove(temp_file_path)
            return JsonResponse({'error': str(e)}, status=500)

    return JsonResponse({'error': 'Invalid request method'}, status=400)


@csrf_exempt
def manage_quarantined_file(request):
    if request.method == 'POST':
        action = request.POST.get('action')  # 'restore' or 'delete'
        file_name = request.POST.get('file_name')
        
        file_path = os.path.join(QUARANTINE_DIR, file_name)

        if not os.path.exists(file_path):
            return JsonResponse({'error': f"File '{file_name}' not found in quarantine."}, status=404)

        if action == 'restore':
            restore_dir = '/path/to/restore/directory'  # Specify where restored files go
            restored_file_path = os.path.join(restore_dir, file_name)
            shutil.move(file_path, restored_file_path)
            return JsonResponse({'status': 'restored', 'message': f"File '{file_name}' has been restored."})

        elif action == 'delete':
            os.remove(file_path)
            return JsonResponse({'status': 'deleted', 'message': f"File '{file_name}' has been deleted."})

        else:
            return JsonResponse({'error': 'Invalid action.'}, status=400)

    return JsonResponse({'error': 'Invalid request method'}, status=400)

#  block firewall
# def get_blocked_programs():
#     return BlockedProgram.objects.all()
from Antivirusproject.settings import admindb
from pymongo.errors import DuplicateKeyError
# firewall
def configure_firewall(request):
    message = None
    if request.method == 'POST':
        action = request.POST.get('action')  # 'allow' or 'block'
        program_path = request.POST.get('program_path')  # Program path from form input
        Data = {
            "program_path": program_path,
            "blocked_at": datetime.datetime.today()
        }

        if not action or not program_path:
            message = 'Invalid parameters. Please provide both action and program path.'
        else:
            try:
                if action == 'allow':
                    subprocess.run(f"netsh advfirewall firewall add rule name='AntivirusProject' dir=in action=allow program={program_path} enable=yes", shell=True, check=True)
                    message = f"Allowed {program_path} through the firewall."
                
                elif action == 'block':
                    # Check if the program is already blocked
                    print("-----program_path--",program_path)
                    existing_program = admindb.adminapp_blockedprogram.find_one({"program_path": Data['program_path']})
                    
                    if existing_program is not None:
                        message = f"{program_path} is already blocked."
                    else:
                        admindb.adminapp_blockedprogram.insert_one(Data)
                        subprocess.run(f"netsh advfirewall firewall add rule name='AntivirusProject' dir=in action=block program={program_path} enable=yes", shell=True, check=True)
                        message = f"Blocked {program_path} in the firewall."
                
                else:
                    message = 'Invalid action. Use "allow" or "block".'
            except subprocess.CalledProcessError as e:
                message = f"Error while configuring firewall: {str(e)}"
            except DuplicateKeyError:
                message = f"{program_path} is already in the blocked list."
            except Exception as e:
                message = f"An unexpected error occurred: {str(e)}"

    # Include blocked programs in the context
    sl = []
    get_data = admindb.adminapp_blockedprogram.find()
    for i in get_data:
        i['iid'] = str(i['_id'])
        del i['_id']
        sl.append(i)

    return render(request, 'Antivirus/firewall.html', {'message': message, 'blocked_programs': sl})


# def configure_firewall(request):
#     if request.method == 'POST':
#         action = request.POST.get('action')  # 'allow' or 'block'
#         program_path = request.POST.get('program_path')  # Program path from form input

#         if not action or not program_path:
#             return render(request, 'firewall.html', {'message': 'Invalid parameters'})

#         try:
#             if action == 'allow':
#                 subprocess.run(f"netsh advfirewall firewall add rule name='AntivirusProject' dir=in action=allow program={program_path} enable=yes", shell=True)
#                 message = f"Allowed {program_path} through the firewall."
#             elif action == 'block':
#                 subprocess.run(f"netsh advfirewall firewall add rule name='AntivirusProject' dir=in action=block program={program_path} enable=yes", shell=True)
#                 message = f"Blocked {program_path} in the firewall."
#             else:
#                 message = 'Invalid action. Use "allow" or "block".'
#         except subprocess.CalledProcessError as e:
#             message = f"Error: {str(e)}"
        
#         return render(request, 'Antivirus/firewall.html', {'message': message})

#     return render(request, 'Antivirus/firewall.html')


# import elevate

# def disable_windows_defender():
#     try:
#         # Request elevated permissions
#         elevate.elevate()  # This will prompt for admin access

#         # Disable Windows Defender via Registry (Admin access needed)
#         subprocess.run([
#             "reg", "add", "HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows Defender", 
#             "/v", "DisableAntiSpyware", "/t", "REG_DWORD", "/d", "1", "/f"
#         ], check=True)
#         print("Windows Defender disabled.")
#     except subprocess.CalledProcessError as e:
#         print(f"Error occurred: {e}")

# disable_windows_defender()


import subprocess
from django.http import HttpResponse

def defenderscan_file(request):
    if request.method == 'GET':
        file_path = "E:\\Arjun\\scan\\virrus_scan.txt"  # E:\Arjun\Antivirusproject
        command = [
            "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",  # Use verified path
            "-Scan",
            "-ScanType", "3",
            "-File", file_path
        ]
        try:
            process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
            stdout, stderr = process.communicate()
            output = stdout if stdout else stderr  # Capture output or error
        except FileNotFoundError:
            output = "MpCmdRun.exe not found. Please verify the path."
        return HttpResponse(output, content_type="text/plain")


import win32evtlog

def fetch_defender_events():
    log_type = 'Microsoft-Windows-Windows Defender/Operational'
    server = 'localhost'  # Local machine
    flags = win32evtlog.EVENTLOG_FORWARDS_READ | win32evtlog.EVENTLOG_SEQUENTIAL_READ
    handle = win32evtlog.OpenEventLog(server, log_type)
    events = win32evtlog.ReadEventLog(handle, flags, 0)
    print("====",events)
    return events

from django.views import View

from django.http import JsonResponse
from rest_framework.views import APIView
import subprocess


def _execute_powershell_command(self, command):
    """Executes a PowerShell command and returns the output."""
    try:
        result = subprocess.run(command, capture_output=True, text=True, shell=True)
        if result.returncode != 0:
            return {"error": f"Command failed with error: {result.stderr.strip()}"}
        return {"output": result.stdout.strip()}
    except Exception as e:
        return {"error": f"Internal Server Error: {str(e)}"}

class DefenderAPI(APIView):

    def _execute_powershell_command(self, command):
        """Executes a PowerShell command and returns the output."""
        try:
            result = subprocess.run(command, capture_output=True, text=True, shell=True)
            if result.returncode != 0:
                return {"error": f"Command failed with error: {result.stderr.strip()}"}
            return {"output": result.stdout.strip()}
        except Exception as e:
            return {"error": f"Internal Server Error: {str(e)}"}

    def post(self, request):
        try:
            # token = request.META.get('HTTP_AUTHORIZATION')
            userId = "123"#dectoken(token)
            if not userId:
                return JsonResponse({'message': "Your token has expired"}, status=401)

            action = request.data.get('action')
            print("========",action)
            if action == 'enable_realtime':
                command = [
                    "powershell", "-Command", 
                    "try { Set-MpPreference -DisableRealtimeMonitoring $false } catch { $_ | Out-String }"
                ]
                response = self._execute_powershell_command(command)
                return JsonResponse(response, safe=False, status=200)

            elif action == 'check_status':
                command = ["powershell", "-Command", "Get-MpComputerStatus"]
                response = self._execute_powershell_command(command)
                return JsonResponse(response, safe=False, status=200)

            elif action == 'scan_file':
                file_path = request.data.get('file_path')
                if not file_path:
                    return JsonResponse({'message': "File path is required"}, status=400)

                command = [
                    "C:\\Program Files\\Windows Defender\\MpCmdRun.exe",
                    "-Scan", 
                    "-ScanType", "3",  # Full scan
                    "-File", file_path
                ]
                response = self._execute_powershell_command(command)
                return JsonResponse(response, safe=False, status=200)

            else:
                return JsonResponse({'message': 'Invalid action'}, status=400)

        except Exception as e:
            return JsonResponse({'message': f'Internal Server Error: {str(e)}'}, status=500)

    def get(self, request):
        return JsonResponse({'message': 'Use POST method to interact with Defender functionalities.'}, status=405)

import psutil
import socket

def get_browser_connections():
    # Get all active connections
    connections = psutil.net_connections(kind='inet')
    urls = []

    for conn in connections:
        # Check if the connection is on port 80 (HTTP) or 443 (HTTPS)
        if conn:  # Check ports only for HTTP and HTTPS
            try:
                # Get the process name
                process = psutil.Process(conn.pid)
                process_name = process.name()
                # Filter for common browser processes
                if process_name.lower() in ["chrome.exe", "firefox.exe", "msedge.exe", "safari.exe"]:
                    remote_address = conn.raddr
                    if remote_address:
                        # Attempt to resolve the remote address to a URL
                        try:
                            # Get the domain name from the IP address
                            domain_name = socket.gethostbyaddr(remote_address[0])[0]
                            # Construct the URL
                            url = f"{'https://' if conn.laddr.port == 443 else 'http://'}{domain_name}"
                            urls.append(url)
                        except socket.herror:
                            # If unable to resolve, you can append the IP address instead
                            url = f"{'https://' if conn.laddr.port == 443 else 'http://'}{remote_address[0]}"
                            urls.append(url)
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue
    
    return urls
print("-------",get_browser_connections())
if __name__ == "__main__":
    active_urls = get_browser_connections()
    print("Active HTTP and HTTPS network connections made by browsers:")
    for url in active_urls:
        print(f"Local Address: ({url})")

import sqlite3
import os

def get_chrome_history():
    history_path = os.path.expanduser("~") + r"\AppData\Local\Google\Chrome\User Data\Default\History"
    try:
        # Connect to the database
        conn = sqlite3.connect(history_path)
        cursor = conn.cursor()
        
        # Execute a query to retrieve URLs from the history
        cursor.execute("SELECT url FROM urls ORDER BY last_visit_time DESC")
        
        # Fetch and print all URLs
        urls = [url[0] for url in cursor.fetchall()]
        conn.close()
        print("-----",urls)
        return urls
    except sqlite3.OperationalError:
        print("Chrome is currently running, please close it to access the history file.")
        return []
    
print("---ds",get_chrome_history)


import subprocess
from django.views.decorators.csrf import csrf_exempt
from django.shortcuts import render

def get_scan_results(scan_type=None):
    try:
        # Choose the command based on the scan type
        if scan_type == "quick":
            command = ["powershell", "-Command", "Start-MpScan -ScanType QuickScan"]
        elif scan_type == "full":
            command = ["powershell", "-Command", "Start-MpScan -ScanType FullScan"]
        elif scan_type == "retrieve":
            command = ["powershell", "-Command", "Get-MpThreatDetection"]
        else:
            return {"error": "Invalid scan type provided."}

        # Run the PowerShell command in a hidden window
        result = subprocess.run(
            command,
            capture_output=True,
            text=True,
            creationflags=subprocess.CREATE_NO_WINDOW  # This hides the PowerShell window
        )

        # Check for errors
        if result.returncode != 0:
            error_message = result.stderr.strip()
            return {"error": f"Command failed with error: {error_message}"}
        # print("=--=",result)
        # Parse the output
        lines = result.stdout.strip().splitlines() if result.stdout else []
        parsed_results = []
        entry = {}
        # print("-*-***",lines)
        for line in lines:
            if line == "":
                if entry:
                    parsed_results.append({
                        "Success": entry.get('ActionSuccess'),
                        "start_scanning_time": entry.get('InitialDetectionTime'),
                        "end_scanning_time": entry.get('LastThreatStatusChangeTime'),
                        "ProcessName": entry.get('ProcessName'),
                        "ThreatStatusErrorCode": entry.get('ThreatStatusErrorCode')
                    })
                    entry = {}
            elif ":" in line:
                key, value = line.split(":", 1)
                entry[key.strip()] = value.strip()
        
        # Append the last entry if any
        if entry:
            parsed_results.append({
                "Success": entry.get('ActionSuccess'),
                "start_scanning_time": entry.get('InitialDetectionTime'),
                "end_scanning_time": entry.get('LastThreatStatusChangeTime'),
                "ProcessName": entry.get('ProcessName'),
                "ThreatStatusErrorCode": entry.get('ThreatStatusErrorCode')
            })

        return parsed_results  # Return as list of dictionaries
    except Exception as e:
        return {"error": f"An exception occurred: {str(e)}"}

@csrf_exempt
def scan_results_view(request):
    result = subprocess.run(["powershell", "-Command", "Get-ExecutionPolicy"], capture_output=True, text=True)
    print("-*-*-*-*",result)
    if "Restricted" in result.stdout:
        print("Execution policy is restricted. Please change it to allow script execution.")
    scan_type = request.GET.get("scan_type", "retrieve")
    results = get_scan_results(scan_type)
    return render(request, "Antivirus/fullscan.html", {'scan_results': results})
   

def stop_scan():
    try:
        # Check if the Windows Defender service is running
        service_check = subprocess.run(
            ["powershell", "-Command", "Get-Service -Name WinDefend | Select-Object -ExpandProperty Status"],
            capture_output=True,
            text=True,
            check=True
        )

        if service_check.stdout.strip() != "Running":
            return {"error": "Windows Defender service is not running."}

        # Attempt to disable real-time protection
        print("====service_check.stdout.strip()===",service_check.stdout.strip())
        result = subprocess.run(
            ["powershell", "-Command", "Set-MpPreference -DisableRealtimeMonitoring $true"],
            capture_output=True,
            text=True,
            check=True
        )
        print("result",result)
        return {"message": "Real-time protection disabled successfully. Scan should stop soon."}

    except subprocess.CalledProcessError as e:
        if e.stderr.strip() == "Set-MpPreference : Operation failed with the following error: 0x%1!x!\nAt line:1 char:1\n+ Set-MpPreference -DisableRealtimeMonitoring $true\n+ ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n    + CategoryInfo            : NotSpecified: (MSFT_MpPreference:root\\Microsoft\\...FT_MpPreference) [Set-MpPreference], CimException\n    + FullyQualifiedErrorId : HRESULT 0xc0000142,Set-MpPreference":
            return {"error": "Insufficient privileges to disable real-time protection. Please run the script as administrator."}
        else:
            return {"error": f"Failed to disable real-time protection: {e.stderr.strip()}"}

    except Exception as e:
        return {"error": f"An unexpected error occurred: {str(e)}"}

@csrf_exempt  # Consider CSRF protection for production environments
def stop_scan_view(request):
    """
    View function to handle stop scan requests and return JSON response.

    Args:
        request (HttpRequest): The incoming HTTP request.

    Returns:
        JsonResponse: A JSON response containing the results of the stop_scan function.
    """

    results = stop_scan()
    return JsonResponse(results)


def render_folderscan_page(request):
    # Render the page with the form to select a folder path
    return render(request, 'Antivirus/folder.html')



# from Tkinter import *
def select_folder(request):
    """This view opens a folder selection dialog and returns the selected path."""
    if request.method == "GET":
        root = Tk()
        root.withdraw()  # Hide the root window
        folder_path = filedialog.askdirectory()  # Open dialog and get folder path
        root.destroy()
        
        if folder_path:
            print("-*--*-",folder_path)
            return JsonResponse({"folder_path": folder_path})
        else:
            return JsonResponse({"error": "No folder selected."}, status=400)
from datetime import datetime     
def folderscanAPI(request):
    if request.method == 'GET':
        folder_path = request.GET.get('folder_path')
        
        # For debugging - print the received folder path
        print("Folder path received:", folder_path)
        
        if folder_path:
            defender_exe = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
            
            # Check if the defender executable exists
            if not os.path.exists(defender_exe):
                return JsonResponse({"result": "Windows Defender is not installed at the expected path."}, status=400)

            # Capture start time
            start_time = datetime.now()

            # Run Windows Defender command with specified folder
            result = subprocess.run(
                [defender_exe, "-Scan", "-ScanType", "3", "-File", folder_path],
                capture_output=True,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            # Capture end time
            end_time = datetime.now()
            
            # Check the output to see if any threats were found
            # print("*-*-*-",result.stdout)
            # if "Threat" in result.stdout or "threat" in result.stdout:
            #     threat_found = True
            # else:
            #     threat_found = False

            # Prepare the JSON response with scan details
            response_data = {
                "folder_path": folder_path,
                "start_time": start_time.strftime("%Y-%m-%d %H:%M:%S"),
                "end_time": end_time.strftime("%Y-%m-%d %H:%M:%S"),
                "duration": str(end_time - start_time),
                "scan_result": result.stdout if result.stdout else result.stderr,
                # "threat_found": threat_found,
            }
            print("**response_data",response_data)
            # Return the JSON response with appropriate status
            if result.returncode == 0:
                response_data["status"] = "Scan completed successfully."
            else:
                response_data["status"] = "Scan encountered an issue."

            return JsonResponse(response_data)
        
        return JsonResponse({"result": "No folder path specified."}, status=400)
        # return render(request , 'Antivirus/folder.html')
    
    if request.method == 'POST':
        try:
            
            folder_path =  request.POST.get('folder_path')
            # Path to Windows Defender's MpCmdRun executable
            defender_exe = r"C:\Program Files\Windows Defender\MpCmdRun.exe"
            
            # Check if the defender executable exists
            if not os.path.exists(defender_exe):
                return "Windows Defender is not installed at the expected path."

            # Run Windows Defender command with specified folder
            result = subprocess.run(
                [defender_exe, "-Scan", "-ScanType", "3", "-File", folder_path],
                capture_output=True,
                text=True
            )

            # Check result and return output
            if result.returncode == 0:
                print("**************",result)
                return f"Scan completed successfully:\n{result.stdout}"
            else:
                return f"Scan failed:\n{result.stderr}"
        except Exception as e:
            return f"An error occurred: {str(e)}"
        
@csrf_exempt  # Use with caution, ideally use CSRF protection for form submissions
def game_booster(request):
    message = None  # Variable to hold the response message
    
    if request.method == 'POST' and 'game_file' in request.FILES:
        game_file = request.FILES['game_file']
        game_file_path = default_storage.save(game_file.name, game_file)
        full_file_path = default_storage.path(game_file_path)  # Get the full path to the saved file
        
        # Start the game process
        process = subprocess.Popen(full_file_path)
        
        # Set high priority for the game process
        game_process = psutil.Process(process.pid)
        game_process.nice(psutil.HIGH_PRIORITY_CLASS)  # For Windows
        
        # Set a success message
        message = f'Boosted {game_file.name} to high priority and launched it!'

    return render(request, 'Antivirus/game_booster.html', {'message': message})


ADOBE_SIGN_API_BASE_URL = "https://api.adobesign.com/api/rest/v6"
ADOBE_CLIENT_ID = "your_client_id"
ADOBE_CLIENT_SECRET = "your_client_secret"
ADOBE_ACCESS_TOKEN = "your_access_token"

# views.py
import requests
from django.conf import settings
from django.http import JsonResponse


def send_document_for_signature(request):
    url = f"{settings.ADOBE_SIGN_API_BASE_URL}/agreements"
    headers = {
        "Authorization": f"Bearer {settings.ADOBE_ACCESS_TOKEN}",
        "Content-Type": "application/json",
    }
    data = {
        "fileInfos": [{"name": "your_document.pdf"}],  # Replace with actual file details
        "name": "Agreement Document",
        "participantSetsInfo": [{
            "memberInfos": [{"email": "signer@example.com"}],  # Replace with signer details
            "role": "SIGNER"
        }],
        "signatureType": "ESIGN",
        "state": "IN_PROCESS"
    }
    response = requests.post(url, headers=headers, json=data)
    
    if response.status_code == 200:
        return JsonResponse(response.json(), status=200)
    else:
        return JsonResponse(response.json(), status=response.status_code)

def upload_document():
    url = f"{settings.ADOBE_SIGN_API_BASE_URL}/transientDocuments"
    headers = {
        "Authorization": f"Bearer {settings.ADOBE_ACCESS_TOKEN}",
    }
    files = {
        'File': ('document.pdf', open('path/to/document.pdf', 'rb')),
    }
    response = requests.post(url, headers=headers, files=files)
    
    if response.status_code == 200:
        return response.json().get("transientDocumentId")
    else:
        raise Exception("Document upload failed.")

battery_saver_mode = False  # Global variable to track Battery Saver mode status

import psutil
from django.shortcuts import render
from django.contrib import messages

# Initialize battery saver mode as False by default
def battery_status(request):
    # Ensure that battery_saver_mode is stored in the session
    if 'battery_saver_mode' not in request.session:
        request.session['battery_saver_mode'] = False

    # Handle POST request to toggle Battery Saver mode
    if request.method == 'POST':
        action = request.POST.get('action')
        if action == 'enable':
            request.session['battery_saver_mode'] = True
            messages.success(request, "Battery Saver Mode Enabled.")
        elif action == 'disable':
            request.session['battery_saver_mode'] = False
            messages.success(request, "Battery Saver Mode Disabled.")

    # Check battery status
    battery = psutil.sensors_battery()
    if battery is None:
        battery_info = "No battery found on this system."
        battery_status = None
        battery_percentage = None
    else:
        battery_percentage = battery.percent
        plugged = battery.power_plugged
        battery_status = "Charging" if plugged else "Not Charging"
        battery_info = f"Battery: {battery_percentage}% - {battery_status}"

    return render(request, 'Antivirus/battery_status.html', {
        'battery_info': battery_info,
        'battery_percentage': battery_percentage,
        'battery_status': battery_status,
        'battery_saver_mode': request.session['battery_saver_mode'],
    })


# Global variable to control the scanning process
scan_running = False

def compute_file_hash(file_path, hash_algorithm='sha256'):
    hash_func = hashlib.new(hash_algorithm)
    try:
        with open(file_path, 'rb') as file:
            while chunk := file.read(8192):
                hash_func.update(chunk)
        return hash_func.hexdigest()
    except (FileNotFoundError, PermissionError) as e:
        print(f"Error reading {file_path}: {e}")
        return None

def scan_directory(directory, scan_type='quick'):
    global scan_running
    scan_running = True  # Set scan running flag to True
    scanned_files = []

    try:
        for dirpath, _, filenames in os.walk(directory):
            if not scan_running:  # Check if the scan should stop
                print("Scan stopped by user.")
                break

            for filename in filenames:
                file_path = os.path.join(dirpath, filename)
                file_hash = compute_file_hash(file_path)
                if file_hash:
                    scanned_files.append(file_path)
    except PermissionError:
        print(f"Skipping directory due to permission issues: {directory}")
    except Exception as e:
        print(f"Error during scanning: {e}")

    return scanned_files

def stop_scan():
    global scan_running
    scan_running = False  # Set scan running flag to False

@csrf_exempt
def scan_api(request):
    if request.method == 'POST':
        data = json.loads(request.body)
        scan_type = data.get('scan_type')
        drive = data.get('drive')

        if scan_type == 'quick':
            if not drive:
                return JsonResponse({'error': 'Drive not specified'}, status=400)

            scanned_files = scan_directory(drive, scan_type='quick')
            return JsonResponse({'status': 'Quick scan completed', 'scanned_files': scanned_files})

        elif scan_type == 'full':
            scanned_files = scan_directory('/')
            return JsonResponse({'status': 'Full scan completed', 'scanned_files': scanned_files})

        else:
            return JsonResponse({'error': 'Invalid scan type'}, status=400)
    
    return JsonResponse({'error': 'Invalid request method'}, status=405)    

@csrf_exempt
def stop_scan_api(request):
    if request.method == 'POST':
        stop_scan()  # Stop the ongoing scan
        return JsonResponse({'status': 'Scan stopped successfully'})
    return JsonResponse({'error': 'Invalid request method'}, status=405)

sl = {
    "MonthYear": "Oct-24",
    "Categories": [
        {
            "Category": "Standard",
            "DailyData": [
                3, 9, 10, 2, 12, 1, 13, 20, 16, 16, 16, 18, 19, 16, 12, 17, 13, 11, 16, 11, 9, 11, 25, 16, 27, 14, 16, 14, 7, 12, 12, 11, 11, 11, 10
            ],
            "Total": 409
        },
        {
            "Category": "Deluxe",
            "DailyData": [
                3, 2, 3, 2, 2, 1, 6, 7, 8, 7, 9, 5, 9, 5, 13, 10, 11, 8, 11, 12, 16, 16, 16, 20, 16, 32, 20, 16, 14, 16, 14, 11, 10, 10, 7
            ],
            "Total": 234
        },
        {
            "Category": "Suite",
            "DailyData": [
                12, 12, 14, 1, 14, 4, 4, 4, 15, 1, 29, 1, 26, 11, 7, 4, 20, 6, 11, 28, 28, 28, 28, 43, 31, 12, 12, 37, 30, 18, 41, 23
            ],
            "Total": 311
        }
    ],
    "GrandTotal": 954
}

def poweBI(request):
    type = request.GET.get('type')
    print("------",type)
    bi=[]
    # poweBIdb.avilable.insert_one(sl)
    if type == 'Av':
        data = poweBIdb.avilable.find()
        for i in  data:
            i['_id'] = str(i['_id'])
            del i['_id']
            bi.append(i) 
    if type == 'ORT':
        data = poweBIdb.ORT.find()
        for i in  data:
            i['_id'] = str(i['_id'])
            del i['_id']
            bi.append(i)  
    if type == None:
        data = poweBIdb.pwerBI.find()
        for i in  data:
            i['_id'] = str(i['_id'])
            del i['_id']
            bi.append(i)
    return JsonResponse({'data': bi}, status=200)