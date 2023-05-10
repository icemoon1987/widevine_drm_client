#!/usr/bin/env python
# -*- coding: utf-8 -*-

######################################################
#
# File Name:  widevine_drm.py
#
# Function:   
#
# Usage:  
#
# Input:  
#
# Output:	
#
# Author: wenhai.pan
#
# Create Time:    2017-12-01 10:44:57
#
######################################################

import sys
reload(sys)
sys.setdefaultencoding("utf-8")
import os
import time
import json
import base64
import urllib2
import hashlib
from Crypto.Cipher import AES
from binascii import b2a_hex, a2b_hex
from datetime import datetime, timedelta


class WidevineDrm(object):

    def __init__(self, provider, key_server_url, aes_signing_key, aes_signing_iv):
        
        self.provider = provider
        self.key_server_url = key_server_url
        self.aes_signing_key = aes_signing_key
        self.aes_signing_iv = aes_signing_iv

        return
    

    def pkcs5padding(self, s, BS=16):
        return s + (BS - len(s) % BS) * chr(BS - len(s) % BS) 


    def get_encryption_info(self, content_id, policy="", tracks=[], drm_types=["WIDEVINE"]):

        # Request information
        key_request_obj = {}
        key_request_obj["content_id"] = base64.b64encode(content_id)
        key_request_obj["policy"] = policy
        key_request_obj["tracks"] = []
        key_request_obj["tracks"].append({"type": "HD"})
        key_request_obj["tracks"].append({"type": "SD"})
        key_request_obj["tracks"].append({"type": "AUDIO"})
        key_request_obj["drm_types"] = []
        key_request_obj["drm_types"].append("WIDEVINE")

        # Serialize to json and base64 encoding
        key_request_json = json.dumps(key_request_obj)
        key_request_base64 = base64.b64encode(key_request_json)

        # Generate AES signature
        sha = hashlib.sha1(key_request_json).digest()

        # use PKCS5 padding
        sha = self.pkcs5padding(sha)

        # Sign with AES
        encryptor = AES.new(self.aes_signing_key, AES.MODE_CBC, self.aes_signing_iv)
        signature = encryptor.encrypt(sha)

        # Base64 encode the signature
        signature = base64.b64encode(signature)

        # Widevine request package
        request_data = json.dumps({
            "request": key_request_base64,
            "signature": signature,
            "signer": self.provider
        })

        # Get key info from widevine and parse the response
        response = urllib2.urlopen(key_server_url, request_data)

        response_data = response.read()
        response_data = json.loads(response_data)

        response_obj = json.loads(base64.b64decode(response_data["response"]))

        return response_obj


if __name__ == "__main__":
    print "test"

    provider = "widevine_test"
    content_id = "fkj3ljaSdfalkr3j"
    policy = ""

    key_server_url = "https://license.uat.widevine.com/cenc/getcontentkey/widevine_test"
    aes_signing_key = b'\x1a\xe8\xcc\xd0\xe7\x98\x5c\xc0\xb6\x20\x3a\x55\x85\x5a\x10\x34\xaf\xc2\x52\x98\x0e\x97\x0c\xa9\x0e\x52\x02\x68\x9f\x94\x7a\xb9'
    aes_signing_iv = b'\xd5\x8c\xe9\x54\x20\x3b\x7c\x9a\x9a\x9d\x46\x7f\x59\x83\x92\x49'

    widevine_drm = WidevineDrm(
        provider=provider,
        key_server_url=key_server_url, 
        aes_signing_key=aes_signing_key, 
        aes_signing_iv=aes_signing_iv)

    key_info = widevine_drm.get_encryption_info(content_id=content_id)

    for track_key in key_info["tracks"]:
        print ""
        print "type = " + track_key["type"]
        print "key_id = " + b2a_hex(base64.b64decode(track_key["key_id"]))
        print "key = " + b2a_hex(base64.b64decode(track_key["key"]))
        print "pssh = " + track_key["pssh"][0]["data"]

    '''
    with open("./crypt0.key", "r") as f:

        data = f.read()
        print len(data)
        print data
        print b2a_hex(data)
    '''
        





