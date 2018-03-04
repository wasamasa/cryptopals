## Recover the key from CBC with IV=Key

# Take your code from the CBC exercise (#16) and modify it so that it
# repurposes the key for CBC encryption as the IV.
#
# Applications sometimes use the key as an IV on the auspices that
# both the sender and the receiver have to know the key already, and
# can save some space by using it as both a key and an IV.
#
# Using the key as an IV is insecure; an attacker that can modify
# ciphertext in flight can get the receiver to decrypt a value that
# will reveal the key.
#
# The CBC code from exercise 16 encrypts a URL string. Verify each
# byte of the plaintext for ASCII compliance (ie, look for high-ASCII
# values). Noncompliant messages should raise an exception or return
# an error that includes the decrypted plaintext (this happens all the
# time in real systems, for what it's worth).
#
# Use your code to encrypt a message that is at least 3 blocks long:
#
#     AES-CBC(P_1, P_2, P_3) -> C_1, C_2, C_3
#
# Modify the message (you are now the attacker):
#
#     C_1, C_2, C_3 -> C_1, 0, C_1
#
# Decrypt the message (you are now the receiver) and raise the
# appropriate error if high-ASCII is found.
#
# As the attacker, recovering the plaintext from the error, extract
# the key:
#
#     P'_1 XOR P'_3

require_relative 'util'

IV = random_bytes(16)
KEY = IV

def encode_cookie(userdata)
  prefix = 'comment1=cooking%20MCs;userdata='
  suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
  input = prefix + userdata.tr(';=', '') + suffix
  raise "invalid ASCII string: #{input}" unless input.ascii_only?
  aes_cbc_encrypt(pkcs7pad(input.bytes, 16), KEY, IV)
end

def decode_cookie(buffer)
  input = str(pkcs7unpad(aes_cbc_decrypt(buffer, KEY, IV)))
  raise "invalid ASCII string: #{input}" unless input.ascii_only?
  output = input.split(';').map { |kv| kv.split('=') }.to_h
  assert(output['admin'] == 'true')
end

def get_error_string
  input = 'A' * (16 * 3)
  cookie = encode_cookie(input)
  16.times { |i| cookie[16 + i] = 0 }
  16.times { |i| cookie[32 + i] = cookie[i] }
  begin
    decode_cookie(cookie)
  rescue RuntimeError => e
    assert(e.message.start_with?('invalid ASCII string:'))
    e.message.slice(22..-1)
  end
end

blocks = get_error_string.bytes.each_slice(16).take(3)
key = xor_buffers(blocks[0], blocks[2])
assert(key == KEY)
