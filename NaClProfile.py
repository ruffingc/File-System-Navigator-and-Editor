# Charles Ruffing
# ruffingc@uci.edu
# 40252524

# NaClProfile.py
# An encrypted version of the Profile class provided by the Profile.py module
# 
# for ICS 32
# by Mark S. Baldwin


# TODO: Install the pynacl library so that the following modules are available
# to your program.
import json
import os
from pathlib import Path
import nacl.utils
from nacl.public import PrivateKey, PublicKey, Box   
from copy import deepcopy

# Import the Profile and Post classes
from Profile import Profile, Post, DsuFileError, DsuProfileError

# mport the NaClDSEncoder module
from NaClDSEncoder import NaClDSEncoder
    
# Subclass the Profile class
class NaClProfile(Profile):

    # create encoder instance for the whole class to use
    encoder = NaClDSEncoder()

    #def __init__(self, public_key=None, private_key=None, keypair=None):
    def __init__(self, dsuserver=None, username=None, password=None):       
        self.public_key:str
        self.private_key:str
        self.keypair:str
        super().__init__(dsuserver, username, password)  


    # Generate a new public encryption key using NaClDSEncoder.
    def generate_keypair(self) -> str:
        self.encoder.generate()
        self.public_key = self.encoder.public_key
        self.private_key = self.encoder.private_key
        self.keypair = self.encoder.keypair
        return self.keypair

    # Imports an existing keypair. Useful when keeping encryption keys in a location other than the
    # dsu file created by this class.
    def import_keypair(self, keypair: str):
        self.keypair = keypair
        keyLength = len(keypair) // 2
        # private key is first
        self.public_key = keypair[:keyLength]
        # public key is from after private key to the end
        self.private_key = keypair[keyLength:]

    # Override the add_post method to encrypt post entries.
    def add_post(self, post: Post) -> None:
        # encrypt the entry with my public key
        entry_enc = self.__encrypt(post.get_entry(), self.public_key)

        # Create new Post with the encrypted entry
        post_enc = Post(entry_enc)
        super().add_post(post_enc)

    # Override the get_posts method to decrypt post entries.
    def get_posts(self) -> list[Post]:
        posts = super().get_posts()
        
        # build list of decrypted posts
        posts_dec:list[Post] = []
        for i in posts: 
            # decrypt the post entry
            entry_dec = self.__decrypt(i.get_entry())   
            # make a copy of the original Post 
            post_dec = deepcopy(i)  
            # set the copy's entry to the decrypted value 
            post_dec.set_entry(entry_dec) 
            # Add the decrypted post to the new list
            posts_dec.append(post_dec)

        return posts_dec
    
    """
    Override the load_profile method to add support for storing a keypair.
    Since the DS Server is now making use of encryption keys rather than username/password attributes, you will 
    need to add support for storing a keypair in a dsu file. The best way to do this is to override the 
    load_profile module and add any new attributes you wish to support.
    The Profile class implementation of load_profile contains everything you need to complete this.
    Just copy the code here and add support for your new attributes.
    """
    def load_profile(self, path: str) -> None:
        p = Path(path)

        if os.path.exists(p) and p.suffix == '.dsu':
            try:
                f = open(p, 'r')
                obj = json.load(f)
                self.username = obj['username']
                self.password = obj['password']
                self.dsuserver = obj['dsuserver']
                self.bio = obj['bio']
                for post_obj in obj['_posts']:
                    post = Post(post_obj['entry'], post_obj['timestamp'])
                    self._posts.append(post)
                # Now add support for the new attributes
                if 'keypair' in obj and 'public_key' in obj and 'private_key' in obj:
                    self.keypair = obj['keypair']
                    self.public_key = obj['public_key']
                    self.private_key = obj['private_key']
                f.close()
            except Exception as ex:
                raise DsuProfileError(ex)
        else:
            raise DsuFileError()

    '''
    Encrypt messages using a 3rd party public key, such as the one that the DS server provides.
    A good design approach might be to create private encrypt and decrypt methods that your add_post, 
    get_posts and this method can call.
    '''
    def encrypt_entry(self, entry:str, public_key:str) -> bytes:
        return self.__encrypt(entry, public_key)

    # encrypt with public key provided and own private key
    def __encrypt(self, entry:str, public_key) -> str:
        box = self.encoder.create_box(self.encoder.encode_private_key(self.private_key), self.encoder.encode_public_key(public_key))
        return self.encoder.encrypt_message(box, entry)

    # decrypt with own private key and own public key  
    def __decrypt(self, entry:str) -> str:
        box = self.encoder.create_box(self.encoder.encode_private_key(self.private_key), self.encoder.encode_public_key(self.public_key))
        return self.encoder.decrypt_message(box, entry)