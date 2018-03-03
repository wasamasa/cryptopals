# -*- coding: utf-8 -*-
## DSA key recovery from nonce

# Step 1: Relocate so that you are out of easy travel distance of us.
#
# Step 2: Implement DSA, up to signing and verifying, including
# parameter generation.
#
# Hah-hah you're too far away to come punch us.
#
# Just kidding you can skip the parameter generation part if you want;
# if you do, use these params:
#
#     p = 800000000000000089e1855218a0e7dac38136ffafa72eda7
#         859f2171e25e65eac698c1702578b07dc2a1076da241c76c6
#         2d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebe
#         ac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2
#         b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc87
#         1a584471bb1
#
#     q = f4f47f05794b256174bba6e9b396a7707e563c5b
#
#     g = 5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119
#         458fef538b8fa4046c8db53039db620c094c9fa077ef389b5
#         322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a047
#         0f5b64c36b625a097f1651fe775323556fe00b3608c887892
#         878480e99041be601a62166ca6894bdd41a7054ec89f756ba
#         9fc95302291
#
# ("But I want smaller params!" Then generate them yourself.)
#
# The DSA signing operation generates a random subkey "k". You know
# this because you implemented the DSA sign operation.
#
# This is the first and easier of two challenges regarding the DSA "k"
# subkey.
#
# Given a known "k", it's trivial to recover the DSA private key "x":
#
#         (s * k) - H(msg)
#     x = ----------------  mod q
#                 r
#
# Do this a couple times to prove to yourself that you grok
# it. Capture it in a function of some sort.
#
# Now then. I used the parameters above. I generated a keypair. My pubkey is:
#
#     y = 84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4
#         abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004
#         e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed
#         1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07b
#         bb283e6633451e535c45513b2d33c99ea17
#
# I signed
#
#     For those that envy a MC it can be hazardous to your health
#     So be friendly, a matter of life and death, just like a etch-a-sketch
#
# (My SHA1 for this string was
# *d2d0714f014a9784047eaeccf956520045c45265*; I don't know what NIST
# wants you to do, but when I convert that hash to an integer I get:
# *0xd2d0714f014a9784047eaeccf956520045c45265*).
#
# I get:
#
#     r = 548099063082341131477253921760299949438196259240
#     s = 857042759984254168557880549501802188789837994940
#
# I signed this string with a broken implemention of DSA that
# generated "k" values between 0 and 2^16. What's my private key?
#
# Its SHA-1 fingerprint (after being converted to hex) is:
#
#     0954edd5e0afe5542a4adf012611a91912a3ec16
#
# Obviously, it also generates the same signature for that string.

require_relative 'util'

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

y = 0x84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17

MESSAGE = "For those that envy a MC it can be hazardous to your health\nSo be friendly, a matter of life and death, just like a etch-a-sketch\n".bytes
MESSAGE_HASH = 'd2d0714f014a9784047eaeccf956520045c45265'.freeze
r = 548099063082341131477253921760299949438196259240
s = 857042759984254168557880549501802188789837994940

assert(SHA1.hexdigest(MESSAGE) == MESSAGE_HASH)

def test_dsa(buffer, params)
  p, q, g = params
  x = rand(1...q)
  y = modexp(g, x, p)
  signature = dsa_sign(buffer, params, x)
  dsa_verify(buffer, signature, params, y)
end

test_dsa(MESSAGE, [p, q, g])

#         H(m) + xr
#     s = --------- mod q
#             k
#
# <=> sk = (H(m) + xr) mod q
#
# <=> sk - xr = H(m) mod q
#
# <=> - xr = (H(m) - sk) mod q
#
# <=> xr = (sk - H(m)) mod q
#
#         sk - H(m)
# <=> x = --------- mod q
#             r

def recover_private_key(buffer, params, signature, k)
  q = params[1]
  r, s = signature
  ((s * k - SHA1.hexdigest(buffer).to_i(16)) * invmod(r, q)) % q
end

def test_key_recovery(buffer, params)
  q = params[1]
  x = rand(1...q)
  k = rand(2...q)
  signature = dsa_sign(buffer, params, x, k)
  assert(x == recover_private_key(buffer, params, signature, k))
end

test_key_recovery(MESSAGE, [p, q, g])

def crack_private_key(buffer, params, signature, y, upper)
  (0..upper).each do |k|
    p, _q, g = params
    x = recover_private_key(buffer, params, signature, k)
    next unless modexp(g, x, p) == y
    info("k: #{k}")
    assert(dsa_sign(MESSAGE, params, x, k) == signature)
    return x
  end
  raise 'failed cracking private key'
end

x = crack_private_key(MESSAGE, [p, q, g], [r, s], y, 2**16)
info("x: 0x#{x.to_s(16)}")
assert(SHA1.hexdigest(x.to_s(16).bytes) ==
       '0954edd5e0afe5542a4adf012611a91912a3ec16')
