require_relative '../util'
require 'openssl'

input = b64decode(File.open('07.txt', &:read))
output = aes_ecb_decrypt(input, 'YELLOW SUBMARINE'.bytes)
puts str(output)
