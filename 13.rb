## ECB cut-and-paste

# Write a k=v parsing routine, as if for a structured cookie. The
# routine should take:
#
#     foo=bar&baz=qux&zap=zazzle
#
# ... and produce:
#
#     {
#       foo: 'bar',
#       baz: 'qux',
#       zap: 'zazzle'
#     }
#
# (you know, the object; I don't care if you convert it to JSON).
#
# Now write a function that encodes a user profile in that format,
# given an email address. You should have something like:
#
#     profile_for("foo@bar.com")
#
# ... and it should produce:
#
#     {
#       email: 'foo@bar.com',
#       uid: 10,
#       role: 'user'
#     }
#
# ... encoded as:
#
#     email=foo@bar.com&uid=10&role=user
#
# Your "profile_for" function should not allow encoding metacharacters
# (& and =). Eat them, quote them, whatever you want to do, but don't
# let people set their email address to "foo@bar.com&role=admin".
#
# Now, two more easy functions. Generate a random AES key, then:
#
# A. Encrypt the encoded user profile under the key; "provide" that to
# the "attacker".
#
# B. Decrypt the encoded user profile and parse it.
#
# Using only the user input to profile_for() (as an oracle to generate
# "valid" ciphertexts) and the ciphertexts themselves, make a
# role=admin profile.

require_relative 'util'

KEY = str(random_bytes(16))

def decode_query_string(input)
  input.split('&').map { |kv| kv.split('=') }.to_h
end

def encode_query_string(hash)
  hash.map { |k, v| "#{k}=#{v}" }.join('&')
end

def profile_for(email)
  profile = { 'email' => email.tr('=&', ''),
              'uid' => 10,
              'role' => 'user' }
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
