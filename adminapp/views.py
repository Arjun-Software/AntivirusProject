from django.shortcuts import render
from django.http import JsonResponse
from rest_framework.views import APIView
import requests
import os
import datetime
from Antivirusproject.settings import admindb
# Create your views here.


def response_messages(response_message, response_data,response_status):
    
    final_response_message = {
        "status":response_status,
        "message": response_message,
        "result": response_data,
        
    }
    return final_response_message


AUTH_SERVER = "http://127.0.0.1:8000/"
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



class scanUrlAPI(APIView):
    def get(self,request):
        try:
            geturl = request.GET.get('url').replace("https://", "").rstrip("/")
            url = "https://www.virustotal.com/api/v3/domains/"+geturl
            print("====0=url==",url)
            headers = {
            "accept": "application/json",
            "x-apikey": "671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850"
            }
            response = requests.get(url, headers=headers)
            print("-*------",response.json())
            response = response.json()
            success_message = response_messages("success", response,200)
            return JsonResponse(success_message, safe=False, status=200)
        except Exception as e:
            message =  {
                    "message": "Internal Server Error {}".format(e)
                }
            error_message = response_messages("failed", message,500)
            return JsonResponse(error_message, safe=False, status=500)
import base64         

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
            print("----------------",re.json())
            success_message = response_messages("success", response,200)
            return JsonResponse(success_message, safe=False, status=200)
        except Exception as e:
            message =  {
                    "message": "Internal Server Error {}".format(e)
                }
            error_message = response_messages("failed", message,500)
            return JsonResponse(error_message, safe=False, status=500)
        
class filescanAPI(APIView):
    def post(self,request):
        try:
            data =  request.data
            getfile = data['file']
            # print("=====",getfile)
            
            fileurl  = "https://www.virustotal.com/api/v3/files"
            files = {"file": open(getfile, "rb")}
            # print("*******",files)
            headers = {
            "accept": "application/json",
            "x-apikey": "671dfacd7749ba03ecb03588d14fb56ffba18a33473bf9c6f416113e939d3850"
            }
            response = requests.post(fileurl, files=files, headers=headers)
            response = response.json()
            id = response['data']['id']
            print("----",response['data']['id'])
            re = "https://www.virustotal.com/api/v3/files/"+id
            print("====",re)
            re = requests.get(re, headers=headers)
            print("----------------",re.json())
            success_message = response_messages("success", response,200)
            return JsonResponse(success_message, safe=False, status=200)
        except Exception as e:
            message =  {
                    "message": "Internal Server Error {}".format(e)
                }
            error_message = response_messages("failed", message,500)
            return JsonResponse(error_message, safe=False, status=500)




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

            print("----------------", file_info_response.json())
            success_message = response_messages("success", response_json, 200)
            return JsonResponse(success_message, safe=False, status=200)
        
        except Exception as e:
            message = {
                "message": "Internal Server Error {}".format(e)
            }
            error_message = response_messages("failed", message, 500)
            return JsonResponse(error_message, safe=False, status=500)
