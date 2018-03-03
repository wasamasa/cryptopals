## DSA nonce recovery from repeated nonce

## Cryptanalytic MVP award.

# This attack (in an elliptic curve group) broke the PS3. It is a
# great, great attack.

# In this file find a collection of DSA-signed messages. (NB: each msg
# has a trailing space.)
#
# These were signed under the following pubkey:
#
#     y = 2d026f4bf30195ede3a088da85e398ef869611d0f68f07
#         13d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b8
#         5519b1c23cc3ecdc6062650462e3063bd179c2a6581519
#         f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430
#         f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d3
#         2971c3de5084cce04a2e147821
#
# (using the same domain parameters as the previous exercise)
#
# It should not be hard to find the messages for which we have
# accidentally used a repeated "k". Given a pair of such messages, you
# can discover the "k" we used with the following formula:
#
#         (m1 - m2)
#     k = --------- mod q
#         (s1 - s2)

## 9th Grade Math: Study It!

# If you want to demystify this, work out that equation from the
# original DSA equations.

## Basic cyclic group math operations want to screw you

# Remember all this math is mod q; s2 may be larger than s1, for
# instance, which isn't a problem if you're doing the subtraction mod
# q. If you're like me, you'll definitely lose an hour to forgetting a
# paren or a mod q. (And don't forget that modular inverse function!)

# What's my private key? Its SHA-1 (from hex) is:
#
#    ca8f6f7c66fa362d40760d135b763eb8527d3d52

require_relative 'util'

# some message have the same r, this is because r is modexp(g, k, p) %
# q where three out of four variables are always the same and if k is
# reused, naturally the result will also be

MESSAGES = File.open('44.txt', &:readlines)
               .map { |line| line.chomp.split(': ')[1] }
               .each_slice(4)
               .map do |msg, s, r, m|
                 { msg: msg, s: s.to_i, r: r.to_i, m: m.to_i(16) }
               end

message, message2 = MESSAGES.group_by { |msg| msg[:r] }
                            .find { |_, v| v.size > 1 }[1]

#          H(m1) + xr             H(m2) + xr
#     s1 = ---------- mod q, s2 = ---------- mod q
#               k                      k
#
#               H(m1) + xr   H(m2) + xr
# <=> s1 - s2 = ---------- - ---------- mod q
#                    k            k
#
#               H(m1) + xr - H(m2) - xr
# <=> s1 - s2 = ----------------------- mod q
#                         k
#
#               H(m1) - H(m2)
# <=> s1 - s2 = ------------- mod q
#                     k
#
# <=> (s1 - s2) * k = (H(m1) - H(m2)) mod q
#
#         H(m1) - H(m2)
# <=> k = ------------- mod q
#            s1 - s2

q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b

m1 = message[:m]
m2 = message2[:m]
r = message[:r]
s1 = message[:s]
s2 = message2[:s]

k = (((m1 - m2) % q) * invmod(s1 - s2, q)) % q
info("k: 0x#{k.to_s(16)}")

#         H(m) + xr
#     s = --------- mod q
#             k
#
# <=> sk = (H(m) + xr) mod q
#
# <=> sk - H(m) = xr mod q
#
#     sk - H(m)
# <=> --------- mod q = x
#         r

x = (((s1 * k - m1) % q) * invmod(r, q)) % q
info("x: 0x#{x.to_s(16)}")
assert(SHA1.hexdigest(x.to_s(16).bytes) ==
       'ca8f6f7c66fa362d40760d135b763eb8527d3d52')
