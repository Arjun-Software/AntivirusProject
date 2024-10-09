import requests
import time

# Replace 'YOUR_API_KEY' with your actual VirusTotal API key
API_KEY = '671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'




def scan_url(url):
    """Submits the URL for scanning to VirusTotal."""
    params = {'apikey': API_KEY, 'url': url}
    response = requests.post(SCAN_URL, data=params)
    
    if response.status_code == 200:
        json_response = response.json()
        scan_id = json_response.get('scan_id')
        print(f"Scan ID: {scan_id}")
        return scan_id
    else:
        print(f"Error submitting URL for scan: {response.status_code}")
        return None

def get_scan_report(scan_id):
    """Fetches the scan report for the given scan_id."""
    params = {'apikey': API_KEY, 'resource': scan_id}
    while True:
        response = requests.get(REPORT_URL, params=params)
        
        if response.status_code == 200:
            json_response = response.json()
            if json_response.get('response_code') == 1:
                return json_response
            else:
                print("Waiting for report to be generated...")
                time.sleep(10)  # Wait for 10 seconds before retrying
        else:
            print(f"Error fetching scan report: {response.status_code}")
            break
    return None

def print_scan_report(report):
    """Prints the results of the scan report."""
    print(f"URL: {report.get('url')}")
    print(f"Scan Date: {report.get('scan_date')}")
    print(f"Positives: {report.get('positives')} / {report.get('total')}")

    scans = report.get('scans')
    for scanner, result in scans.items():
        print(f"{scanner}: {result['result']}")
    
if __name__ == "__main__":
    url_to_scan = input("Enter the URL to scan: ")
    
    # Step 1: Submit the URL for scanning
    scan_id = scan_url(url_to_scan)
    
    if scan_id:
        # Step 2: Retrieve the scan report
        report = get_scan_report(scan_id)
        
        # Step 3: Print the scan report
        if report:
            print_scan_report(report)

"""
from django.shortcuts import render
from django.http import HttpResponse
from django.conf import settings

def index(request):
    context = {}
    if request.method == 'POST':
        url = request.POST.get('url')
        params = {'apikey': VIRUSTOTAL_API_KEY, 'url': url}
        scan_response = requests.post(SCAN_URL, data=params)
        
        if scan_response.status_code == 200:
            scan_id = scan_response.json().get('scan_id')
            report_params = {'apikey': VIRUSTOTAL_API_KEY, 'resource': scan_id}
            report_response = requests.get(REPORT_URL, params=report_params)
            context['report'] = report_response.json()
        else:
            context['error'] = 'Unable to scan URL'
    
    return render(request, 'urlscan.html', context)


# urlscanner/views.py
import requests
from django.http import JsonResponse
from django.views.decorators.csrf import csrf_exempt
import json

API_KEY = '671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850'
SCAN_URL = 'https://www.virustotal.com/vtapi/v2/url/scan'
REPORT_URL = 'https://www.virustotal.com/vtapi/v2/url/report'

@csrf_exempt
def scan_url(request):
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            url = data['url']
            params = {'apikey': API_KEY, 'url': url}
            
            # Submit URL for scanning
            scan_response = requests.post(SCAN_URL, data=params)
            if scan_response.status_code == 200:
                scan_id = scan_response.json().get('scan_id')
                
                # Retrieve scan report
                report_params = {'apikey': API_KEY, 'resource': scan_id}
                report_response = requests.get(REPORT_URL, params=report_params)
                report_data = report_response.json()
                
                return JsonResponse(report_data)
            else:
                return JsonResponse({'error': 'Unable to scan URL'}, status=500)
        except KeyError:
            return JsonResponse({'error': 'Invalid data'}, status=400)
    return JsonResponse({'message': 'Only POST requests allowed'}, status=405)
"""


import json

# Sample JSON data
data = {
    'id': 'kiaantechnology.com',
    'type': 'domain',
    'links': {'self': 'https://www.virustotal.com/api/v3/domains/kiaantechnology.com'},
    'attributes': {
        'last_dns_records': [
            {'type': 'MX', 'ttl': 1200, 'priority': 5, 'value': 'mx1-hosting.jellyfish.systems'},
            {'type': 'NS', 'ttl': 21600, 'value': 'dns1.namecheaphosting.com'},
            # ... additional DNS records
        ],
        'tld': 'com',
        'whois': 'Admin City: Reykjavik\nAdmin Country: IS\nAdmin Email: 165de20aec2cf2eas@withheldforprivacy.com\n...',
        'registrar': 'NAMECHEAP INC',
        'last_analysis_stats': {'malicious': 0, 'suspicious': 0, 'undetected': 32, 'harmless': 62, 'timeout': 0},
        'reputation': 0,
        'last_analysis_results': {
            'Acronis': {'method': 'blacklist', 'engine_name': 'Acronis', 'category': 'harmless', 'result': 'clean'},
            '0xSI_f33d': {'method': 'blacklist', 'engine_name': '0xSI_f33d', 'category': 'undetected', 'result': 'unrated'},
            # ... more analysis results
        }
    }
}

# Extract domain information
domain_id = data['id']
domain_type = data['type']
domain_self_link = data['links']['self']
registrar = data['attributes']['registrar']
last_analysis_stats = data['attributes']['last_analysis_stats']
last_analysis_results = data['attributes']['last_analysis_results']

# Print the basic domain information
print(f"Domain ID: {domain_id}")
print(f"Domain Type: {domain_type}")
print(f"Self Link: {domain_self_link}")
print(f"Registrar: {registrar}")

# Print last analysis stats
print("\nLast Analysis Stats:")
for key, value in last_analysis_stats.items():
    print(f"{key.capitalize()}: {value}")

# Print analysis results
print("\nLast Analysis Results:")
for engine, result in last_analysis_results.items():
    print(f"Engine: {engine}, Result: {result['result']}, Category: {result['category']}")

