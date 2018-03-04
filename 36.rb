## Implement Secure Remote Password (SRP)

# To understand SRP, look at how you generate an AES key from DH; now,
# just observe you can do the "opposite" operation an generate a
# numeric parameter from a hash. Then:
#
# Replace A and B with C and S (client & server)
#
# C & S
#     Agree on N=[NIST Prime], g=2, k=3, I (email), P (password)
# S
#     Generate salt as random integer
#     Generate string xH=SHA256(salt|password)
#     Convert xH to integer x somehow (put 0x on hexdigest)
#     Generate v=g**x % N
#     Save everything but x, xH
# C->S
#     Send I, A=g**a % N (a la Diffie Hellman)
# S->C
#     Send salt, B=kv + g**b % N
# S, C
#     Compute string uH = SHA256(A|B), u = integer of uH
# C
#     Generate string xH=SHA256(salt|password)
#     Convert xH to integer x somehow (put 0x on hexdigest)
#     Generate S = (B - k * g**x)**(a + u * x) % N
#     Generate K = SHA256(S)
# S
#     Generate S = (A * v**u) ** b % N
#     Generate K = SHA256(S)
# C->S
#     Send HMAC-SHA256(K, salt)
# S->C
#     Send "OK" if HMAC-SHA256(K, salt) validates
#
# You're going to want to do this at a REPL of some sort; it may take
# a couple tries.
#
# It doesn't matter how you go from integer to string or string to
# integer (where things are going in or out of SHA256) as long as you
# do it consistently. I tested by using the ASCII decimal
# representation of integers as input to SHA256, and by converting the
# hexdigest to an integer when processing its output.
#
# This is basically Diffie Hellman with a tweak of mixing the password
# into the public keys. The server also takes an extra step to avoid
# storing an easily crackable password-equivalent.

require_relative 'util'

ROLE = ENV['ROLE'] || 'C'
C = '/tmp/cryptopals-36-C'.freeze
S = '/tmp/cryptopals-36-S'.freeze
NIST_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

assert(%w(C S).include?(ROLE))

ensure_pipe(C)
ensure_pipe(S)

# the protocol description looks incomplete/wrong, the great benefit
# of SRP is that you don't send a password or hashed equivalent at any
# time, however the first step is about agreeing on N, g, k, I and P
# and the second one requires the server knowing that password

# judging from wikipedia it should instead look like this (with |
# denoting concatenation):

# prelude:
#
# C & S
#     Agree on N=[NIST Prime], g=2, k=3

# signup:
#
# C
#     Choose I (email) and P (password)
# C
#     Generate salt as random integer
#     Generate string xH=SHA256(salt|password)
#     Convert xH to integer x somehow (put 0x on hexdigest)
#     Generate v=g**x % N
# C->S
#     Send I, salt, v
# S
#     Save salt and v indexed by I

# login (unchanged):
#
# C->S
#     Send I, A=g**a % N (a la Diffie Hellman)
# S->C
#     Send salt, B=kv + g**b % N
# S, C
#     Compute string uH = SHA256(A|B), u = integer of uH
# C
#     Generate string xH=SHA256(salt|password)
#     Convert xH to integer x somehow (put 0x on hexdigest)
#     Generate S = (B - k * g**x)**(a + u * x) % N
#     Generate K = SHA256(S)
# S
#     Generate S = (A * v**u) ** b % N
#     Generate K = SHA256(S)
# C->S
#     Send HMAC-SHA256(K, salt)
# S->C
#     Send "OK" if HMAC-SHA256(K, salt) validates

assert(sha256_hmac([], []) ==
       'b613679a0814d9ec772f95d778c35fc5ff1697c493715653c6c712144292c5ad')

N = NIST_PRIME

def signup_client(email, password)
  g = 2
  salt = rand(1..1024)
  x = sha256_hexdigest("#{salt}#{password}".bytes).to_i(16)
  v = modexp(g, x, N)
  snd(S, "#{email} #{salt} #{v}")
  info("signed up with #{email}")
end

def signup_server
  _I, salt, v = rcv(S).split(' ')
  salt = salt.to_i
  v = v.to_i
  info("signup from #{_I}")
  [_I, salt, v]
end

def login_client(email, password)
  g = 2
  k = 3
  a = rand(1..1024)
  _A = modexp(g, a, N)
  snd(S, "#{email} #{_A}")
  salt, _B = rcv(C).split(' ')
  _B = _B.to_i
  u = sha256_hexdigest("#{_A}#{_B}".bytes).to_i(16)
  x = sha256_hexdigest("#{salt}#{password}".bytes).to_i(16)
  _S = modexp(_B - k * modexp(g, x, N), a + u * x, N)
  _K = sha256_hexdigest(_S.to_s.bytes)
  snd(S, sha256_hmac(_K.bytes, salt.to_s.bytes))
  assert(rcv(C) == 'OK')
end

def login_server(credentials)
  g = 2
  k = 3
  _I, _A = rcv(S).split(' ')
  _A = _A.to_i
  salt, v = credentials[_I]
  b = rand(1..1024)
  _B = (k * v + modexp(g, b, N)) % N
  snd(C, "#{salt} #{_B}")
  u = sha256_hexdigest("#{_A}#{_B}".bytes).to_i(16)
  _S = modexp(_A * modexp(v, u, N), b, N)
  _K = sha256_hexdigest(_S.to_s.bytes)
  hmac = rcv(S)
  ok = sha256_hmac(_K.bytes, salt.to_s.bytes) == hmac
  snd(C, ok ? 'OK' : 'FAIL')
end

if ROLE == 'C'
  email = "#{random_word}@example.com"
  password = random_word
  signup_client(email, password)
  login_client(email, password)
else
  credentials = {}
  _I, salt, v = signup_server
  credentials[_I] = [salt, v]
  login_server(credentials)
end

info('login successful!')
