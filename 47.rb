## Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

## Degree of difficulty: moderate

# These next two challenges are the hardest in the entire set.

# Let us Google this for you: "Chosen ciphertext attacks against
# protocols based on the RSA encryption standard"
#
# This is Bleichenbacher from CRYPTO '98; I get a bunch of .ps
# versions on the first search page.
#
# Read the paper. It describes a padding oracle attack on
# PKCS#1v1.5. The attack is similar in spirit to the CBC padding
# oracle you built earlier; it's an "adaptive chosen ciphertext
# attack", which means you start with a valid ciphertext and
# repeatedly corrupt it, bouncing the adulterated ciphertexts off the
# target to learn things about the original.
#
# This is a common flaw even in modern cryptosystems that use RSA.
#
# It's also the most fun you can have building a crypto attack. It
# involves 9th grade math, but also has you implementing an algorithm
# that is complex on par with finding a minimum cost spanning tree.
#
# The setup:
#
# - Build an oracle function, just like you did in the last exercise,
#   but have it check for plaintext[0] == 0 and plaintext[1] == 2.
# - Generate a 256 bit keypair (that is, p and q will each be 128 bit
#   primes), [n, e, d].
# - Plug d and n into your oracle function.
# - PKCS1.5-pad a short message, like "kick it, CC", and call it
#   "m". Encrypt to to get "c".
# - Decrypt "c" using your padding oracle.
#
# For this challenge, we've used an untenably small RSA modulus (you
# could factor this keypair instantly). That's because this exercise
# targets a specific step in the Bleichenbacher paper --- Step 2c,
# which implements a fast, nearly O(log n) search for the plaintext.
#
# Things you want to keep in mind as you read the paper:
#
# - RSA ciphertexts are just numbers.
# - RSA is "homomorphic" with respect to multiplication, which means
#   you can multiply c * RSA(2) to get a c' that will decrypt to
#   plaintext * 2. This is mindbending but easy to see if you play
#   with it in code --- try multiplying ciphertexts with the RSA
#   encryptions of numbers so you know you grok it.
# - What you need to grok for this challenge is that Bleichenbacher
#   uses multiplication on ciphertexts the way the CBC oracle uses
#   XORs of random blocks.
# - A PKCS#1v1.5 conformant plaintext, one that starts with 00:02,
#   must be a number between 02:00:00...00 and 02:FF:FF..FF --- in
#   other words, 2B and 3B-1, where B is the bit size of the modulus
#   minus the first 16 bits. When you see 2B and 3B, that's the idea
#   the paper is playing with.
#
# To decrypt "c", you'll need Step 2a from the paper (the search for
# the first "s" that, when encrypted and multiplied with the
# ciphertext, produces a conformant plaintext), Step 2c, the fast
# O(log n) search, and Step 3.
#
# Your Step 3 code is probably not going to need to handle multiple
# ranges.
#
# We recommend you just use the raw math from paper (check, check,
# double check your translation to code) and not spend too much time
# trying to grok how the math works.

require_relative 'util'
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
