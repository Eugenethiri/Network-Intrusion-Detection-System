#!/usr/bin/env python3
'''    
this shows the pushover setup for receiving notifications
requirements are #API KEY TOKEN and  #USER KEY TOKEN. Create keys on the pushover app and make changes on the script
'''
import http.client
import urllib

def send_pushover_notification(token, user_key, message):
    conn = http.client.HTTPSConnection("api.pushover.net:443")
    conn.request("POST", "/1/messages.json",
        urllib.parse.urlencode({
            "token":  "xxxxxxxxxxxxxxxxxxxxxxx", #API KEY TOKEN
            "user":  "xxxxxxxxxxxxxxxxxxxxxxxx",  #USER KEY TOKEN
            "message": "ATTENTION !intrusion inside your network has been detected, network interference is needed  ",
        }), { "Content-type": "application/x-www-form-urlencoded" })
    conn.getresponse()

# usage
send_pushover_notification("your_app_token", "your_user_key", "Test notification")









"""    
OG script found at the pushover app, changed to my preferences to fit my requirements for the IDS

import httplib, urllib
conn = httplib.HTTPSConnection("api.pushover.net:443")
conn.request("POST", "/1/messages.json",
  urllib.urlencode({
    "token": "APP_TOKEN",
    "user": "USER_KEY",
    "message": "hello world",
  }), { "Content-type": "application/x-www-form-urlencoded" })
conn.getresponse()
"""
