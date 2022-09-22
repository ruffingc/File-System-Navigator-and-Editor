# Charles Ruffing
# ruffingc@uci.edu
# 40252524

# NaClDSEncoder_test.py
# Simple test harness for the NaClDSEncoder class
# 
# ICS 32
# Mark S. Baldwin

import unittest
from NaClDSEncoder import NaClDSEncoder
from nacl.public import PrivateKey, PublicKey, Box

class TestNaClDSEncoder(unittest.TestCase):

    def test_generate(self):
        # create an NaClDSEncoder object
        nacl_enc = NaClDSEncoder()
        # generate new keys
        nacl_enc.generate()

        # typically in a unittest printing this way is unnecessary
        # including here for demonstration purposes...
        # use print to display the keys, notice how the keypair is 
        # just the public and private keys combined.
        print('\n')
        print(f'keypair: {nacl_enc.keypair}')
        print(f'public key: {nacl_enc.public_key}')
        print(f'private key: {nacl_enc.private_key}')

        self.assertEqual(len(nacl_enc.keypair), 88)
        self.assertEqual(nacl_enc.public_key, nacl_enc.keypair[:44])
        self.assertEqual(nacl_enc.private_key, nacl_enc.keypair[44:])
    
    def test_encode_public(self):
        print('!!test_encode_public')
        # Use the NaClDSEncoder to create new keys
        test_keys = NaClDSEncoder()
        test_keys.generate()

        # Test the NaClDSEncoder using the test_keys
        nacl_enc = NaClDSEncoder()
        pkey = nacl_enc.encode_public_key(test_keys.public_key)
        self.assertEqual(type(pkey), PublicKey)
    
    def test_encode_private(self):
        print('!!test_encode_private')
        # Use the NaClDSEncoder to create new keys
        test_keys = NaClDSEncoder()
        test_keys.generate()

        # Test the NaClDSEncoder using the test_keys
        nacl_enc = NaClDSEncoder()
        prvkey = nacl_enc.encode_private_key(test_keys.private_key)
        self.assertEqual(type(prvkey), PrivateKey)


if __name__ == '__main__':
    unittest.main()