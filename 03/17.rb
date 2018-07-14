require_relative '../util'

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
KEY = random_bytes(16)

def encrypt_credentials
  iv = random_bytes(16)
  output = aes_cbc_encrypt(pkcs7pad(INPUT, 16), KEY, iv)
  [iv, output]
end

def check_credentials(iv, buffer)
  output = aes_cbc_decrypt(buffer, KEY, iv)
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
