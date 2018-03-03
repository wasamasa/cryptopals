## Implement a SHA-1 keyed MAC

# Find a SHA-1 implementation in the language you code in.

## Don't cheat. It won't work.

# Do not use the SHA-1 implementation your language already provides
# (for instance, don't use the "Digest" library in Ruby, or call
# OpenSSL; in Ruby, you'd want a pure-Ruby SHA-1).

# Write a function to authenticate a message under a secret key by
# using a secret-prefix MAC, which is simply:
#
#     SHA1(key || message)
#
# Verify that you cannot tamper with the message without breaking the
# MAC you've produced, and that you can't produce a new MAC without
# knowing the secret key.

require_relative 'sha1'
require_relative 'util'

require 'digest/sha1'
STOCK_SHA1 = Digest::SHA1.new

assert(SHA1.hexdigest('test'.bytes) == STOCK_SHA1.hexdigest('test'))

KEY = random_word
PLAINTEXT = b64decode('"WW91ciBndWVzcyBpcyBnb29kIGFzIG15IGd1ZXNz"')
MAC = sha1_mac(PLAINTEXT, KEY)

def verify(buffer, mac)
  mac == sha1_mac(buffer, KEY)
end

def mutated_string(string)
  mutated = string.clone
  index = rand(0...mutated.size)
  mutated[index] = (mutated[index].ord ^ 1).chr
  mutated
end

def mutated_buffer(buffer)
  mutated = buffer.clone
  index = rand(0...mutated.size)
  mutated[index] ^= 1
  mutated
end

assert(verify(PLAINTEXT, MAC))
assert(!verify(mutated_buffer(PLAINTEXT), MAC))
assert(!verify(PLAINTEXT, mutated_string(MAC)))
