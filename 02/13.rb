require_relative '../util'

KEY = random_bytes(16)

def profile_for(email)
  email = email.tr('=&', '')
  profile = { email: email, uid: 10, role: 'user' }
  encode_query_string(profile)
end

assert(!profile_for('foo@bar.com&role=admin').include?('role=admin'))

def encrypt_profile(input)
  aes_ecb_encrypt(pkcs7pad(input, 16), KEY)
end

def decrypt_profile(input)
  decode_query_string(str(pkcs7unpad(aes_ecb_decrypt(input, KEY))))
end

# email=AAAAAAAAAA|admin\v\v\v\v\v\v\v\v\v\v\v|AAA&uid=10&role=|user\f\f\f\f\f\f\f\f\f\f\f\f
# email=AAAAAAAAAA|AAA&uid=10&role=|admin\v\v\v\v\v\v\v\v\v\v\v|

input = "AAAAAAAAAAadmin\v\v\v\v\v\v\v\v\v\v\vAAA"
ciphertext = encrypt_profile(profile_for(input).bytes)
block0 = ciphertext.slice(0, 16)
block1 = ciphertext.slice(16, 16)
block2 = ciphertext.slice(32, 16)
ciphertext = block0 + block2 + block1

profile = decrypt_profile(ciphertext)
info("Profile: #{profile}")
assert(profile['role'] == 'admin')
