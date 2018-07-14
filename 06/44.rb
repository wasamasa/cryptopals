require_relative '../util'

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
