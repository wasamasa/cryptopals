require_relative '../util'
require 'set'

P = generate_prime(128)
Q = generate_prime(128)
E = 2**16 + 1
PUBLIC, PRIVATE = make_rsa_keys(P, Q, E)
MESSAGE = 'kick it, CC'.bytes
MODULUS_SIZE = 256

def pkcs1_v15_pad(buffer, modulus_size)
  prefix = [0x00, 0x02]
  suffix = [0x00]
  padding_size = modulus_size / 8 - prefix.size - suffix.size - buffer.size
  raise 'message too long' if padding_size < 1
  padding = random_bytes(padding_size, (1..255))
  prefix + padding + suffix + buffer
end

def pkcs1_v15_unpad(buffer, modulus_size)
  buffer = leftpad(buffer, modulus_size / 8, 0)
  separator_index = buffer.drop(2).index(0)
  assert(separator_index && separator_index + 1 < buffer.size)
  buffer[(separator_index + 3)..-1]
end

def padding_oracle(c)
  message = rsa_decrypt(c, PRIVATE)
  padding_size = MODULUS_SIZE / 8 - message.size
  message = Array.new(padding_size, 0) + message if padding_size > 0
  assert(message.size == MODULUS_SIZE / 8)
  message[0..1] == [0x00, 0x02]
end

CIPHERTEXT = rsa_encrypt(pkcs1_v15_pad(MESSAGE, MODULUS_SIZE), PUBLIC)
assert(padding_oracle(CIPHERTEXT))
assert(pkcs1_v15_unpad(rsa_decrypt(CIPHERTEXT, PRIVATE), MODULUS_SIZE) ==
       MESSAGE)

def ceil(x, y)
  x / y + (x % y != 0 ? 1 : 0)
end

def floor(x, y)
  x / y
end

e, n = PUBLIC
k = MODULUS_SIZE / 8
s0 = 1
c0 = CIPHERTEXT * modexp(s0, e, n)
B = 2**(8 * (k - 2))
B2 = 2 * B
B3 = 3 * B

def step_2a(c0)
  e, n = PUBLIC
  s1 = ceil(n, B3)
  loop do
    return s1 if padding_oracle((c0 * modexp(s1, e, n)) % n)
    s1 += 1
  end
end

def step_2c(c0, _M, s)
  e, n = PUBLIC
  a, b = _M.first
  r = ceil((b * s - B2) * 2, n)
  loop do
    lower = ceil(B2 + r * n, b)
    upper = ceil(B3 + r * n, a)
    (lower...upper).each do |si|
      return si if padding_oracle((c0 * modexp(si, e, n)) % n)
    end
    r += 1
  end
end

def step_3(_M, si)
  _, n = PUBLIC
  intervals = Set.new
  _M.each do |a, b|
    lower = ceil(a * si - B3 + 1, n)
    upper = ceil(b * si - B2, n)
    (lower...upper).each do |r|
      a_ = [a, ceil(B2 + r * n, si)].max
      b_ = [b, floor(B3 - 1 + r * n, si)].min
      intervals << [a_, b_] if a_ <= b_
    end
  end
  intervals
end

_M = Set.new([[B2, B3 - 1]])
s = step_2a(c0)
info("s1: #{s}")
loop do
  _M = step_3(_M, s)
  info("M: #{_M.to_a}")
  raise "can't handle multiple intervals" unless _M.size == 1
  break if _M.first[0] == _M.first[1]
  s = step_2c(c0, _M, s)
  info("s: #{s}")
end

a = _M.first[0]
m = (a * invmod(s0, n)) % n
info("m: #{str(pkcs1_v15_unpad(number_to_buffer(m), MODULUS_SIZE))}")
