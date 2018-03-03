## Create the MT19937 stream cipher and break it

# You can create a trivial stream cipher out of any PRNG; use it to
# generate a sequence of 8 bit outputs and call those outputs a
# keystream. XOR each byte of plaintext with each successive byte of
# keystream.
#
# Write the function that does this for MT19937 using a 16-bit
# seed. Verify that you can encrypt and decrypt properly. This code
# should look similar to your CTR code.
#
# Use your function to encrypt a known plaintext (say, 14 consecutive
# 'A' characters) prefixed by a random number of random characters.
#
# From the ciphertext, recover the "key" (the 16 bit seed).
#
# Use the same idea to generate a random "password reset token" using
# MT19937 seeded from the current time.
#
# Write a function to check if any given password token is actually
# the product of an MT19937 PRNG seeded with the current time.

require_relative 'util'

SEED = rand(0..0xFFFF)
info("seed: #{SEED}")
plaintext = b64decode('VWhoLCBzaW5jZSAnOS01LCBtb21tYSBiZWVuIHdvcmtpbmcgbmluZS1maXZl')
assert(mt19937_decrypt(mt19937_encrypt(plaintext, SEED), SEED) == plaintext)

KNOWN_PLAINTEXT = Array.new('A'.ord, 14)

def random_encryption
  prefix_size = rand(2..18)
  prefix = random_bytes(prefix_size)
  plaintext = prefix + KNOWN_PLAINTEXT
  mt19937_encrypt(plaintext, SEED)
end

def check_remainder(rng, suffix)
  KNOWN_PLAINTEXT.each_with_index do |byte, i|
    return false unless byte == rng.extract_byte ^ suffix[i]
  end
  true
end

def crack_seed
  ciphertext = random_encryption
  prefix_size = ciphertext.size - KNOWN_PLAINTEXT.size
  suffix = ciphertext.drop(prefix_size)
  (0..0xFFFF).each do |seed|
    rng = MT19937.new(seed)
    prefix_size.times { rng.extract_number }
    return seed if check_remainder(rng, suffix)
  end
  raise("couldn't crack seed")
end

seed = crack_seed
assert(seed == SEED)
info("cracked seed: #{seed}")

PASSWORD_TOKEN_SIZE = 10

def make_password_token
  seed = Time.now.to_i
  info("seed: #{seed}")
  rng = MT19937.new(seed)
  bytes = (0...PASSWORD_TOKEN_SIZE).map { rng.extract_byte }
  b64encode(bytes)
end

def weak_password_token?(token)
  seed = Time.now.to_i
  rng = MT19937.new(seed)
  bytes = (0...PASSWORD_TOKEN_SIZE).map { rng.extract_byte }
  weak = bytes == b64decode(token)
  info('weak password token detected') if weak
  weak
end

assert(!weak_password_token?(b64encode(random_bytes(PASSWORD_TOKEN_SIZE))))
assert(weak_password_token?(make_password_token))
