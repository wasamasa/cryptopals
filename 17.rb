## The CBC padding oracle

# This is the best-known attack on modern block-cipher cryptography.
#
# Combine your padding code and your CBC code to write two functions.
#
# The first function should select at random one of the following 10
# strings:
#
#     MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
#     MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
#     MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
#     MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
#     MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
#     MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
#     MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
#     MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
#     MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
#     MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
#
# ... generate a random AES key (which it should save for all future
# encryptions), pad the string out to the 16-byte AES block size and
# CBC-encrypt it under that key, providing the caller the ciphertext
# and IV.
#
# The second function should consume the ciphertext produced by the
# first function, decrypt it, check its padding, and return true or
# false depending on whether the padding is valid.

## What you're doing here.

# This pair of functions approximates AES-CBC encryption as its
# deployed serverside in web applications; the second function models
# the server's consumption of an encrypted session token, as if it was
# a cookie.

# It turns out that it's possible to decrypt the ciphertexts provided
# by the first function.
#
# The decryption here depends on a side-channel leak by the decryption
# function. The leak is the error message that the padding is valid or
# not.
#
# You can find 100 web pages on how this attack works, so I won't
# re-explain it. What I'll say is this:
#
# The fundamental insight behind this attack is that the byte 01h is
# valid padding, and occur in 1/256 trials of "randomized" plaintexts
# produced by decrypting a tampered ciphertext.
#
# 02h in isolation is not valid padding.
#
# 02h 02h is valid padding, but is much less likely to occur randomly
# than 01h.
#
# 03h 03h 03h is even less likely.
#
# So you can assume that if you corrupt a decryption AND it had valid
# padding, you know what that padding byte is.
#
# It is easy to get tripped up on the fact that CBC plaintexts are
# "padded". Padding oracles have nothing to do with the actual padding
# on a CBC plaintext. It's an attack that targets a specific bit of
# code that handles decryption. You can mount a padding oracle on any
# CBC block, whether it's padded or not.

require_relative 'util'

B = 16

INPUTS = [
  'MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=',
  'MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=',
  'MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==',
  'MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==',
  'MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl',
  'MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==',
  'MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==',
  'MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=',
  'MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=',
  'MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93'
].map { |input| b64decode(input) }

INPUT = random_choice(INPUTS)
KEY = str(random_bytes(16))

def encrypt_credentials
  iv = random_bytes(16)
  output = aes_cbc_encrypt(pkcs7pad(INPUT, 16), iv, KEY)
  [iv, output]
end

def check_credentials(iv, buffer)
  output = aes_cbc_decrypt(buffer, iv, KEY)
  ignore_errors { pkcs7unpad(output) }
end

def decrypt_byte(iv, block, known)
  c = random_bytes(B)
  p = known.length + 1
  known.each_with_index { |x, i| c[B - i - 1] = x ^ p ^ iv[B - i - 1] }
  i = 0
  loop do
    c[B - p] = i
    break if check_credentials(c, block)
    raise "Couldn't guess byte" if i > 256
    i += 1
  end
  iv[B - p] ^ i ^ p
end

def decrypt_block(iv, buffer, n)
  iv = buffer.slice((n - 1) * B, B) if n > 0
  block = buffer.slice(n * B, B)
  known = []
  B.times { known << decrypt_byte(iv, block, known) }
  known.reverse
end

def decrypt
  iv, buffer = encrypt_credentials
  n = buffer.length / B
  (0...n).flat_map { |i| decrypt_block(iv, buffer, i) }
end

puts str(pkcs7unpad(decrypt))
