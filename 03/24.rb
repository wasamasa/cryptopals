require_relative '../util'

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
