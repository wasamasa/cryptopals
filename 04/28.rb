require_relative '../sha1'
require_relative '../util'

require 'digest/sha1'
STOCK_SHA1 = Digest::SHA1.new

assert(SHA1.hexdigest('test'.bytes) == STOCK_SHA1.hexdigest('test'))

KEY = random_word.bytes
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
