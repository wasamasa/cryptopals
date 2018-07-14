require_relative '../util'

MESSAGE = b64decode('dGVzdA==')

p = 0x800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1
q = 0xf4f47f05794b256174bba6e9b396a7707e563c5b
g = 0x5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291

def test_dsa_g0(buffer, p, q)
  g = 0
  params = [p, q, g]
  x = rand(1...q)
  y = modexp(g, x, p)
  signature = dsa_sign(buffer, params, x)
  dsa_verify(buffer, signature, params, y)
  dsa_verify(random_bytes(16), signature, params, y)
end

test_dsa_g0(MESSAGE, p, q)
# this reveals that r is 0, v also becomes 0 (due to one factor being
# 0) and makes the verification pass

def test_dsa_g_p1(buffer, p, q, y, signature)
  g = p + 1
  params = [p, q, g]
  dsa_verify(buffer, signature, params, y)
end

x = rand(1...q)
y = modexp(g, x, p)
z = 2
r = modexp(y, z, p) % q
s = (r * invmod(z, q)) % q
test_dsa_g_p1('Hello, world'.bytes, p, q, y, [r, s])
test_dsa_g_p1('Goodbye, world'.bytes, p, q, y, [r, s])
