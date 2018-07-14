require 'base64'
require 'openssl'
require 'set'

ENGLISH_HISTOGRAM = { ' ' => 0.14,
                      'e' => 0.12,
                      't' => 0.09,
                      :other => 0.09,
                      'a' => 0.08,
                      'o' => 0.07,
                      'i' => 0.06,
                      'n' => 0.06,
                      's' => 0.06,
                      'h' => 0.06,
                      'r' => 0.05,
                      'd' => 0.04,
                      'l' => 0.04,
                      'c' => 0.02,
                      'u' => 0.02,
                      'm' => 0.02,
                      'w' => 0.02,
                      'f' => 0.02,
                      'g' => 0.02,
                      'y' => 0.01,
                      'p' => 0.01,
                      'b' => 0.01,
                      'v' => 0.01,
                      'k' => 0.01,
                      'j' => 0.01,
                      'x' => 0.00,
                      'q' => 0.00,
                      'z' => 0.00 }.freeze

def assert(condition)
  raise('assertion failed') unless condition
end

def ignore_errors
  yield
  true
rescue StandardError
  false
end

def assert_error(&block)
  raise 'exception not raised' if ignore_errors(&block)
end

def log(prefix, message)
  STDERR.puts "[#{prefix}] #{message}"
end

def info(message)
  log('info', message)
end

def str(bytes)
  bytes.pack('C*')
end

def b64decode(string)
  Base64.decode64(string).bytes
end

def b64encode(bytes)
  Base64.strict_encode64(str(bytes))
end

def hexdecode(string)
  [string].pack('H*').bytes
end

def hexencode(bytes)
  str(bytes).unpack('H*')[0]
end

def xor_buffers(a, b)
  raise 'buffers must be of same length' unless a.length == b.length
  result = Array.new(a.length)
  a.each_index { |i| result[i] = a[i] ^ b[i] }
  result
end

def xor_buffer_with_byte(buffer, byte)
  result = Array.new(buffer.size)
  result.each_index { |i| result[i] = buffer[i] ^ byte }
  result
end

def xor_buffer_with_bytes(buffer, bytes)
  result = Array.new(buffer.size)
  result.each_index do |i|
    byte = bytes[i % bytes.length]
    result[i] = buffer[i] ^ byte
  end
  result
end

def frequencies(string)
  result = Hash.new { |h, k| h[k] = 0 }
  total = string.length
  string.chars.each { |char| result[char] += 1 }
  result.each { |k, v| result[k] = v.to_f / total }
  result
end

def chi_squared(hist1, hist2)
  score = 0
  hist1.each do |k, v1|
    v2 = hist2[k] || 0
    next if v1.zero?
    score += (v1 - v2)**2 / v1
  end
  score
end

def printable?(string)
  string[/^[[:print:]]*$/]
end

def english_score(string)
  return 0 unless printable?(string)
  input = string.downcase.tr('^ a-z', '.')
  histogram = frequencies(input)
  histogram[:other] = histogram['.'] || 0
  histogram.delete('.')
  score = 1 / chi_squared(ENGLISH_HISTOGRAM, histogram)
  score *= 2 if histogram[:other] < 0.05
  score
end

def popcount(x)
  x.to_s(2).count('1')
end

def hamming(buf1, buf2)
  raise 'buffers must be of same length' unless buf1.length == buf2.length
  result = 0
  buf1.length.times { |i| result += popcount(buf1[i].ord ^ buf2[i].ord) }
  result
end

def aes_ecb_internal(mode, buffer, key)
  assert((buffer.size % 16).zero?)
  cipher = OpenSSL::Cipher.new('AES-128-ECB')
  cipher.send(mode)
  cipher.key = str(key)
  cipher.padding = 0 # decryption will otherwise fail
  result = cipher.update(str(buffer)) + cipher.final
  result.bytes
end

def aes_ecb_decrypt(buffer, key)
  aes_ecb_internal(:decrypt, buffer, key)
end

def aes_ecb_encrypt(buffer, key)
  aes_ecb_internal(:encrypt, buffer, key)
end

def decode_query_string(input)
  input.split('&').map { |kv| kv.split('=') }.to_h
end

def encode_query_string(hash)
  hash.map { |k, v| "#{k}=#{v}" }.join('&')
end

def aes_cbc_decrypt(buffer, key, iv)
  assert((buffer.size % 16).zero?)
  blocks = buffer.each_slice(16).to_a
  last = iv
  result = []
  blocks.each_with_index do |block|
    output = aes_ecb_decrypt(block, key)
    result += xor_buffers(last, output)
    last = block
  end
  result
end

def aes_cbc_encrypt(buffer, key, iv)
  assert((buffer.size % 16).zero?)
  blocks = buffer.each_slice(16).to_a
  last = iv
  result = []
  blocks.each do |block|
    last = aes_ecb_encrypt(xor_buffers(last, block), key)
    result += last
  end
  result
end

def find_duplicate(array)
  seen = Set.new
  array.each do |item|
    return item if seen.include?(item)
    seen << item
  end
  nil
end

def pkcs7pad(buffer, block_size)
  raise 'invalid block size' unless block_size < 256
  # taken from https://tools.ietf.org/html/rfc2315#section-10.3
  padding_length = block_size - buffer.size % block_size
  padding = Array.new(padding_length, padding_length)
  buffer + padding
end

def pkcs7unpad(buffer)
  size = buffer[-1]
  padding = buffer.slice(-size, size)
  raise 'invalid padding' unless size > 0 && size < 256 &&
                                 padding.all? { |b| b == size }
  buffer[0...-size]
end

def random_bytes(size, limit = 256)
  (0...size).map { rand(limit) }
end

def random_choice(items)
  items[rand(0...items.size)]
end

def long_bytes_le(x)
  [x].pack('q<').bytes
end

# skip, offset and count are measured in 16-byte blocks
def aes_ctr_internal(buffer, key, nonce, skip = 0, count = nil, offset = 0)
  nonce = long_bytes_le(nonce)
  blocks = buffer.each_slice(16).drop(skip).to_a
  blocks = blocks.take(count) if count
  result = []
  blocks.each_with_index do |block, i|
    intermediate = aes_ecb_encrypt(nonce + long_bytes_le(i + offset), key)
    result += xor_buffers(block, intermediate.take(block.length))
  end
  result
end

alias aes_ctr_decrypt aes_ctr_internal
alias aes_ctr_encrypt aes_ctr_internal

def lowest(n, w)
  n & ((1 << w) - 1)
end

class Integer
  def to_b(width = 32)
    to_s(2).rjust(width, '0')
  end
end

require_relative 'mt19937'

def mt19937_internal(buffer, seed)
  rng = MT19937.new(seed)
  buffer.map { |byte| byte ^ rng.extract_byte }
end

alias mt19937_encrypt mt19937_internal
alias mt19937_decrypt mt19937_internal

def pb(buffer)
  puts format('[%s]', buffer.map { |byte| format('%03d', byte) }.join(', '))
end

def hmac(buffer, key, block_size)
  key = hexdecode(yield key) if key.size > block_size
  key += Array.new(block_size - key.size, 0) if key.size < block_size
  opad = xor_buffers(key, Array.new(block_size, 0x5c))
  ipad = xor_buffers(key, Array.new(block_size, 0x36))
  yield(opad + hexdecode(yield ipad + buffer))
end

require_relative 'sha1'

def sha1_mac(buffer, key)
  SHA1.hexdigest(key + buffer)
end

def sha1_hmac(buffer, key)
  block_size = 64
  hmac(buffer, key, block_size) { |bytes| SHA1.hexdigest(bytes) }
end

def make_sha1_key(int, width = 16)
  SHA1.hexdigest(int.to_s.bytes).slice(0, width).bytes
end

require_relative 'md4'

def md4_mac(buffer, key)
  MD4.hexdigest(key + buffer)
end

WORDS = File.open('/usr/share/dict/words', &:readlines).map(&:chomp)

def random_word
  WORDS.sample
end

def modexp(base, exponent, modulus)
  b = OpenSSL::BN.new(base)
  e = OpenSSL::BN.new(exponent)
  m = OpenSSL::BN.new(modulus)
  b.mod_exp(e, m).to_i
end

def generate_dh_keys(p, g)
  private = rand(1..1024) % p
  public = modexp(g, private, p)
  [private, public]
end

def ensure_pipe(name)
  ignore_errors { `mkfifo #{name} 2>/dev/null` }
end

def snd(path, msg)
  File.open(path, 'w') { |f| f.puts msg }
end

def rcv(path)
  File.open(path, 'r') { |f| f.gets.chomp }
end

def sha256_hexdigest(bytes)
  OpenSSL::Digest::SHA256.hexdigest(str(bytes))
end

def sha256_hmac(buffer, key)
  block_size = 64
  hmac(buffer, key, block_size) { |bytes| sha256_hexdigest(bytes) }
end

def invmod(a, n)
  OpenSSL::BN.new(a).mod_inverse(OpenSSL::BN.new(n)).to_i
end

def generate_prime(bits = 128)
  OpenSSL::BN.generate_prime(bits).to_i
end

def lcm(a, b)
  (a * b) / a.gcd(b)
end

def make_rsa_keys(p, q, e = 3)
  n = p * q
  et = (p - 1) * (q - 1)
  assert(e.gcd(et) == 1)
  d = invmod(e, et)
  public_key = [e, n]
  private_key = [d, n]
  [public_key, private_key]
end

def buffer_to_number(buffer)
  hexencode(buffer).to_i(16)
end

def number_to_buffer(number)
  hex = number.to_s(16) # to_s doesn't pad
  hex = '0' + hex if hex.length.odd?
  hexdecode(hex)
end

def icbrt(x)
  (0..x).bsearch { |r| r**3 >= x }
end

def rsa_encrypt(buffer, public_key)
  m = buffer_to_number(buffer)
  e, n = public_key
  modexp(m, e, n)
end

def rsa_decrypt(c, private_key)
  d, n = private_key
  m = modexp(c, d, n)
  number_to_buffer(m)
end

def random_digit
  rand(0..9)
end

def md5_hexdigest(bytes)
  OpenSSL::Digest::MD5.hexdigest(str(bytes))
end

def dsa_sign(buffer, params, x, k = nil)
  p, q, g = params
  k ||= rand(2...q)
  r = modexp(g, k, p) % q
  s = ((SHA1.hexdigest(buffer).to_i(16) + x * r) * invmod(k, q)) % q
  [r, s]
end

def dsa_verify(buffer, signature, params, y)
  r, s = signature
  p, q, g = params
  w = invmod(s, q)
  u1 = (SHA1.hexdigest(buffer).to_i(16) * w) % q
  u2 = (r * w) % q
  v = ((modexp(g, u1, p) * modexp(y, u2, p)) % p) % q
  assert(v == r)
end

def leftpad(buffer, size, item)
  return buffer if buffer.size >= size
  padding_size = size - buffer.size
  Array.new(padding_size, item) + buffer
end

def rightpad(buffer, size, item)
  return buffer if buffer.size >= size
  padding_size = size - buffer.size
  buffer + Array.new(padding_size, item)
end

def cbc_mac(buffer, key, iv)
  hexencode(aes_cbc_encrypt(buffer, key, iv).slice(-16, 16))
end

def merkle_damgard_pad(buffer, block_size, input_size = nil)
  input_size ||= buffer.size
  size_block = long_bytes_le(input_size)
  padding_size = block_size - ((input_size + size_block.size) % block_size) - 1
  buffer + [1] + Array.new(padding_size, 0) + size_block
end

def merkle_damgard(buffer, iv, block_size)
  merkle_damgard_pad(buffer, block_size).each_slice(block_size) do |block|
    iv = yield(block, iv)
  end
  iv
end

def aes_ecb_compress(block, iv)
  aes_ecb_encrypt(block, rightpad(iv, 16, 0)).slice(0, iv.size)
end

def aes_hash(message, iv)
  merkle_damgard(message, iv, 16) { |block, iv| aes_ecb_compress(block, iv) }
end
