## Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

## Cryptanalytic MVP award

# This is an extraordinarily useful attack. PKCS#1v15 padding, despite
# being totally insecure, is the default padding used by RSA
# implementations. The OAEP standard that replaces it is not widely
# implemented. This attack routinely breaks SSL/TLS.

# This is a continuation of challenge #46; it implements the complete
# BB'98 attack.
#
# Set yourself up the way you did in #47, but this time generate a 768
# bit modulus.
#
# To make the attack work with a realistic RSA keypair, you need to
# reproduce step 2b from the paper, and your implementation of Step 3
# needs to handle multiple ranges.
#
# The full Bleichenbacher attack works basically like this:
#
# - Starting from the smallest 's' that could possibly produce a
#   plaintext bigger than 2B, iteratively search for an 's' that
#   produces a conformant plaintext.
# - For our known 's1' and 'n', solve m1=m0s1-rn (again: just a
#   definition of modular multiplication) for 'r', the number of times
#   we've wrapped the modulus.
# - 'm0' and 'm1' are unknowns, but we know both are conformant
#   PKCS#1v1.5 plaintexts, and so are between [2B,3B].
# - We substitute the known bounds for both, leaving only 'r' free,
#   and solve for a range of possible 'r' values. This range should be
#   small!
# - Solve m1=m0s1-rn again but this time for 'm0', plugging in each
#   value of 'r' we generated in the last step. This gives us new
#   intervals to work with. Rule out any interval that is outside
#   2B,3B.
# - Repeat the process for successively higher values of
#   's'. Eventually, this process will get us down to just one
#   interval, whereupon we're back to exercise #47.
#
# What happens when we get down to one interval is, we stop blindly
# incrementing 's'; instead, we start rapidly growing 'r' and backing
# it out to 's' values by solving m1=m0s1-rn for 's' instead of 'r' or
# 'm0'. So much algebra! Make your teenage son do it for you! *Note:
# does not work well in practice*

require_relative 'util'
require 'set'

P = generate_prime(512)
Q = generate_prime(256)
E = 2**16 + 1
PUBLIC, PRIVATE = make_rsa_keys(P, Q, E)
MESSAGE = 'kick it, CC'.bytes
MODULUS_SIZE = 768

def pkcs1_v15_pad(buffer, modulus_size)
  prefix = [0x00, 0x02]
  suffix = [0x00]
  padding_size = modulus_size / 8 - prefix.size - suffix.size - buffer.size
  raise 'message too long' if padding_size < 1
  padding = (0...padding_size).map { rand(1..255) }
  prefix + padding + suffix + buffer
end

def pkcs1_v15_unpad(buffer, modulus_size)
  buffer = leftpad(buffer, modulus_size / 8)
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

def step_2b(c0, s)
  e, n = PUBLIC
  loop do
    s += 1
    return s if padding_oracle((c0 * modexp(s, e, n)) % n)
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
  break if _M.size == 1 && _M.first[0] == _M.first[1]
  if _M.size == 1
    s = step_2c(c0, _M, s)
  else
    s = step_2b(c0, s)
  end
  info("s: #{s}")
end

a = _M.first[0]
m = (a * invmod(s0, n)) % n
info("m: #{str(pkcs1_v15_unpad(number_to_buffer(m), MODULUS_SIZE))}")
