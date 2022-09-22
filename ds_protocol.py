# Charles Ruffing
# ruffingc@uci.edu
# 40252524

# ds_protocol.py

# Starter code for assignment 3 in ICS 32 Programming with Software Libraries in Python

# Replace the following placeholders with your information.

# Charles Ruffing
# ruffingc@uci.edu
# 40252524

import json
from collections import namedtuple
import time

# Namedtuple to hold the values retrieved from json messages.
# TODO: update this named tuple to use DSP protocol keys
DataTuple = namedtuple('DataTuple', ['foo','baz'])


def extract_json(json_msg:str) -> DataTuple:
  '''
  Call the json.loads function on a json string and convert it to a DataTuple object
  
  TODO: replace the pseudo placeholder keys with actual DSP protocol keys
  '''
  try:
    json_obj = json.loads(json_msg)
    #foo = json_obj['token']
    #baz = json_obj['message']['entry']
  except json.JSONDecodeError:
    print("Json cannot be decoded.")
  return json_obj

#print(extract_json('{"token":"user_token", "bio": {"entry": "Hello World!","timestamp": "1603167689.3928561"}}')['bio']['entry'])

def join(username, password, public_key):
    # Now join the DS server with my public key
    join_msg = '{"join": {"username": "'+username+'","password": "'+password+'","token":"'+public_key+'"}}'
    return join_msg


def post(token, message):
    post_msg = '{"token":"'+token+'", "post":{"entry": "'+message+'","timestamp": "'+str(time.time())+'"}}'
    return post_msg


def bio(token, bio):
    newBio = '{"token":"'+token+'", "bio": {"entry": "'+bio+'","timestamp": "'+str(time.time())+'"}}'
    return newBio