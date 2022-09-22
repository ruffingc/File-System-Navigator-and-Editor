# Charles Ruffing
# ruffingc@uci.edu
# 40252524

# Starter code for assignment 3 in ICS 32 Programming with Software Libraries in Python

# Replace the following placeholders with your information.

# Charles Ruffing
# ruffingc@uci.edu
# 40252524
import socket
import json
import ds_protocol
from NaClProfile import NaClProfile

def send(port:int, message:str, profile:NaClProfile):
    '''
    The send function joins a ds server and sends a message, bio, or both
    :param port: The port where the ICS 32 DS server is accepting connections.
    :param message: The message to be sent to the server.
    :param profile: The user NaclProfile
    '''
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as client:
        client.connect((profile.dsuserver, port))
        sending = client.makefile('w')
        receive = client.makefile('r')
        # Now join server with my public_key
        sending.write(ds_protocol.join(profile.username, profile.password, profile.public_key))
        sending.flush()
        srv_msg = receive.readline()
        print(srv_msg)
        if ds_protocol.extract_json(srv_msg)['response']['type'] == "error":
            print(ds_protocol.extract_json(srv_msg)['response']['message'])
            return False
        elif ds_protocol.extract_json(srv_msg)['response']['type'] == "ok":
            print(ds_protocol.extract_json(srv_msg)['response']['message'])
            # Now store DS server's public key to use when encrypting messages before sending to server
            server_public_key = ds_protocol.extract_json(srv_msg)['response']['token']

            # Now instead of sending back the server token, send my public_key
            # sends message to server
            if message != None:
                if len(message) != 0 and message.isspace() == False:
                    # Now encrypt the message with server's public key retrieved from response token
                    message_enc = profile.encrypt_entry(message, server_public_key)
                    # Now send the encrypted message to the server
                    sending.write(ds_protocol.post(profile.public_key, message_enc))
                    sending.flush()
                    srv_msg = receive.readline()
                    # prints response from server to shell
                    print(ds_protocol.extract_json(srv_msg)['response']['message'])
                else:
                    return False
            else:
                print("Error: there is nothing contained in this message.")
            # sends bio as well if it's a string
            if profile.bio != None:
                if len(profile.bio) != 0:
                    # Now encrypt the bio with server's public key retrieved from response token
                    bio_enc = profile.encrypt_entry(profile.bio, server_public_key)
                    sending.write(ds_protocol.bio(profile.public_key, bio_enc))
                    sending.flush()
                    srv_msg = receive.readline()
                    print(ds_protocol.extract_json(srv_msg)['response']['message'])
                #else:
                #    print("Error: there is nothing contained in this bio.")
                #    return False
            #else:
            #    print("Error: there is nothing contained in this bio.")
            #    return False
    return True
