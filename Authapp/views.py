from django.shortcuts import render

# Create your views here.
from django.shortcuts import render, redirect
from rest_framework.views import APIView
from django.http import JsonResponse ,HttpResponse

from datetime import datetime
import redis
from django.conf import settings
import json
import requests
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from  .myapp import *
import jwt
from jwcrypto import jwk,jwe
from jwcrypto.common import json_encode,json_decode
key = jwk.JWK.generate(kty='oct', size=256)
#redis_instance =  redis.StrictRedis(host='3.108.221.100', port=6379,password = "3embed", db=0,socket_timeout=None, connection_pool=None, errors='strict', unix_socket_path=None,decode_responses=True)
class AccessToken2API(APIView):
    
    #key='<jwcrypto.jwk.JWK object at 0x000002B1240D82E8>'
    def post(self, request):
        try:

            #key=self.key
            #print('------66666666---------')
            json_data=request.data

            private_keys=privateval()
            public_keys=publicval()
            passphrase = b"myname"
            private_key = serialization.load_pem_private_key(private_keys, password=passphrase, backend=default_backend())
            encoded = jwt.encode(json_data, private_key, algorithm="RS256")
            #key=keyval()
            #print(encoded)
            payload = encoded #.decode()
            jwetoken = jwe.JWE(payload.encode('utf-8'),
                        json_encode({"alg": "A256KW",
                                    "enc": "A256CBC-HS512"}))
            jwetoken.add_recipient(key)
            enc = jwetoken.serialize()
            aa=json.loads(enc)
            encode1="Bearer "+aa['protected']+'.'+aa['ciphertext']+'.'+aa['encrypted_key']+'.'+aa['tag']+'.'+aa['iv']
            success_message={'message':'success','data':encode1}
            return JsonResponse(success_message, safe=False, status=200)
        except Exception as e:
            print("*******",e)
            message = [
                {
                    "message": "Internal Server Error"
                }
            ]
            return JsonResponse(message, safe=False, status=500)

def decrypt(id):
    encode1 =str(id)
    #print("!11111111111111111111111", encode1)
    decval1=encode1[51:]
    decval = decval1[:-2]
    if "":
        #if redis_instance.get(decval):
        success_message={'message':'success','datas':{"datas":"not available"}}
        return JsonResponse(success_message, safe=False, status=200)
    else:
        print(decval)
        dd=decval.split('.')
        x="{\"ciphertext\":\""+dd[1]+"\",\"encrypted_key\":\""+dd[2]+"\",\"iv\":\""+dd[4]+"\",\"protected\":\""+dd[0]+"\",\"tag\":\""+dd[3]+"\"}"
        #print('------------',x)
        jwetoken = jwe.JWE()
        jwetoken.deserialize(x)
        jwetoken.decrypt(key)
        payload = jwetoken.payload
        print(payload)        
        decode= jwt.decode(payload, options={"verify_signature": False})
        #print('----------',decode)
        success_message={'message':'success','data':decode}
        return JsonResponse(success_message, safe=False, status=200)


def logout(id):
    newval = str(id)
    encode1 =str(id)
    decval1=encode1[50:]
    decval = decval1[:-2]
    dd=decval.split('.')
    x="{\"ciphertext\":\""+dd[1]+"\",\"encrypted_key\":\""+dd[2]+"\",\"iv\":\""+dd[4]+"\",\"protected\":\""+dd[0]+"\",\"tag\":\""+dd[3]+"\"}"
    jwetoken = jwe.JWE()
    jwetoken.deserialize(x)
    jwetoken.decrypt(key)
    payload = jwetoken.payload
    print(payload)        
    decode= jwt.decode(payload, options={"verify_signature": False})
    expire = 3600
    #redis_instance.set(decval,decode['userId'],expire)
    success_message={'message':'success','data':decode}
    return JsonResponse(success_message, safe=False, status=200)



