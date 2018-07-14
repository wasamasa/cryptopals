require_relative '../util'

input = b64decode('L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
key = 'YELLOW SUBMARINE'.bytes
nonce = 0

puts str(aes_ctr_decrypt(input, key, nonce))
assert(aes_ctr_encrypt(aes_ctr_decrypt(input, key, nonce), key, nonce) == input)
