require_relative '../util'

input = b64decode(File.open('10.txt', &:read))
iv = Array.new(16, 0)
key = 'YELLOW SUBMARINE'.bytes

# sanity check
assert(input == aes_cbc_decrypt(aes_cbc_encrypt(input, key, iv), key, iv))

output = aes_cbc_decrypt(input, 'YELLOW SUBMARINE'.bytes, iv)
puts str(output)
