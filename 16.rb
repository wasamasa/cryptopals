## CBC bitflipping attacks

# Generate a random AES key.
#
# Combine your padding code and CBC code to write two functions.
#
# The first function should take an arbitrary input string, prepend
# the string:
#
#     "comment1=cooking%20MCs;userdata="
#
# .. and append the string:
#
#     ";comment2=%20like%20a%20pound%20of%20bacon"
#
# The function should quote out the ";" and "=" characters.
#
# The function should then pad out the input to the 16-byte AES block
# length and encrypt it under the random AES key.
#
# The second function should decrypt the string and look for the
# characters ";admin=true;" (or, equivalently, decrypt, split the
# string on ";", convert each resulting string into 2-tuples, and look
# for the "admin" tuple).
#
# Return true or false based on whether the string exists.
#
# If you've written the first function properly, it should not be
# possible to provide user input to it that will generate the string
# the second function is looking for. We'll have to break the crypto
# to do that.
#
# Instead, modify the ciphertext (without knowledge of the AES key) to
# accomplish this.
#
# You're relying on the fact that in CBC mode, a 1-bit error in a
# ciphertext block:
#
# * Completely scrambles the block the error occurs in
#
# * Produces the identical 1-bit error(/edit) in the next ciphertext
# block.

## Stop and think for a second.

# Before you implement this attack, answer this question: why does CBC
# mode have this property?

require_relative 'util'

KEY = random_bytes(16)
IV = random_bytes(16)

# this CBC feature seems to be about error recovery/tolerance, if
# corruption has been detected, one could retransmit the two faulty
# blocks and keep the remaining ones

def encode_cookie(userdata)
  prefix = 'comment1=cooking%20MCs;userdata='
  suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
  input = prefix + userdata.tr(';=', '') + suffix
  aes_cbc_encrypt(pkcs7pad(input.bytes, 16), KEY, IV)
end

def decode_cookie(buffer)
  input = str(pkcs7unpad(aes_cbc_decrypt(buffer, KEY, IV)))
  info("Decoded string: #{input}")
  output = input.split(';').map { |kv| kv.split('=') }.to_h
  info("Decoded data: #{output}")
  assert(output['admin'] == 'true')
end

# ('<'.ord^1).chr #=> '='
# (':'.ord^1).chr #=> ';'
input = 'AAAAAAAAAAAAAAAA:admin<true:A<AA'
cookie = encode_cookie(input)
cookie[32] ^= 1
cookie[38] ^= 1
cookie[43] ^= 1
cookie[45] ^= 1
decode_cookie(cookie)
