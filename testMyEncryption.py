# Charles Ruffing
# ruffingc@uci.edu
# 40252524

from Profile import Profile, Post
from NaClProfile import NaClProfile

np = NaClProfile("168.235.86.101", "testuser", "testpw")
kp = np.generate_keypair()
#print(np.public_key)
#print(np.private_key)
#print(np.keypair)

# Test encryption with 3rd party public key
ds_pubkey = "jIqYIh2EDibk84rTp0yJcghTPxMWjtrt5NW4yPZk3Cw="
ee = np.encrypt_entry("Encrypted Message for DS Server", ds_pubkey)
print(ee)

# Add a post to the profile and check that it is decrypted.
np.add_post(Post("Hello Salted World!"))
p_list = np.get_posts()
print(p_list[0].get_entry())

# Save the profile
np.save_profile('C:\\ws-ics32\\test.dsu')

print("Open DSU file to check if message is encrypted.")
input("Press Enter to Continue")

# Create a new NaClProfile object and load the dsu file.
np2 = NaClProfile("168.235.86.101", "testuser", "testpw")
np2.load_profile('C:\\ws-ics32\\test.dsu')
# Import the keys
np2.import_keypair(kp)

# Verify the post decrypts properly
p_list = np2.get_posts()
print(p_list[0].get_entry())