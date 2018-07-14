require_relative '../util'

ROLE = ENV['ROLE'] || 'C'
C = '/tmp/cryptopals-38-C'.freeze
S = '/tmp/cryptopals-38-S'.freeze
NIST_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

assert(%w(C S).include?(ROLE))

ensure_pipe(C)
ensure_pipe(S)

# much like with challenge 36, the description is subtly wrong again
# (if the server knew the password and salt, why would it need to
# crack them from the hash?), instead it should look like this:

# prelude:
#
# C & S
#     Agree on N=[NIST Prime], g=2

# signup:
#
# C
#     Choose I (email) and P (password)
#     Generate salt as random integer
#     x = SHA256(salt|password)
#     v = g**x % n
# C->S
#     Send I, salt, v
# S
#     Save salt and v indexed by I

# login:
#
# C->S
#     I, A = g**a % n
# S->C
#     salt, B = g**b % n, u = 128 bit random number
# C
#     x = SHA256(salt|password)
#     S = B**(a + ux) % n
#     K = SHA256(S)
# S
#     S = (A * v ** u)**b % n
#     K = SHA256(S)
# C->S
#     Send HMAC-SHA256(K, salt)
# S->C
#     Send "OK" if HMAC-SHA256(K, salt) validates

# this also means that the server shouldn't just make up a salt and
# instead take the salt as given from the client

N = NIST_PRIME

def signup_client(email, password)
  g = 2
  salt = rand(1..1024)
  x = sha256_hexdigest("#{salt}#{password}".bytes).to_i(16)
  v = modexp(g, x, N)
  snd(S, "#{email} #{salt} #{v}")
  info("signed up with #{email}, #{password}")
end

def signup_server
  _I, salt, v = rcv(S).split(' ')
  info("signup from #{_I}")
  [_I, salt.to_i, v.to_i]
end

def login_client(email, password)
  g = 2
  a = rand(1..1024)
  _A = modexp(g, a, N)
  snd(S, "#{email} #{_A}")
  salt, _B, u = rcv(C).split(' ').map(&:to_i)
  x = sha256_hexdigest("#{salt}#{password}".bytes).to_i(16)
  _S = modexp(_B, a + u * x, N)
  _K = sha256_hexdigest(_S.to_s.bytes)
  snd(S, sha256_hmac(_K.bytes, salt.to_s.bytes))
  assert(rcv(C) == 'OK')
  info('login successful!')
end

def login_server(credentials)
  g = 2
  _I, _A = rcv(S).split(' ')
  _A = _A.to_i
  salt, v = credentials[_I]
  b = rand(1..1024)
  _B = modexp(g, b, N)
  u = rand(2**127...2**128)
  snd(C, "#{salt} #{_B} #{u}")
  _S = modexp(_A * modexp(v, u, N), b, N)
  _K = sha256_hexdigest(_S.to_s.bytes)
  hmac = rcv(S)
  ok = sha256_hmac(_K.bytes, salt.to_s.bytes) == hmac
  snd(C, ok ? 'OK' : 'FAIL')
  info('login successful!')
end

def bad_login_server(credentials)
  g = 2
  _I, _A = rcv(S).split(' ')
  _A = _A.to_i
  salt, v = credentials[_I]
  b = rand(1..1024)
  _B = modexp(g, b, N)
  u = rand(2**127...2**128)
  snd(C, "#{salt} #{_B} #{u}")
  _S = modexp(_A * modexp(v, u, N), b, N)
  _K = sha256_hexdigest(_S.to_s.bytes)
  hmac = rcv(S)
  snd(C, 'OK')
  info('cracking password...')
  password = crack_hmac(hmac, [g, salt, v, u, b, _A])
  info("cracked password: #{password}")
end

def crack_hmac(hmac, params)
  g, salt, v, u, b, _A = params
  password = WORDS.find do |word|
    x = sha256_hexdigest("#{salt}#{word}".bytes).to_i(16)
    modexp(g, x, N) == v
  end
  raise 'failed finding password' unless password
  _S = modexp(_A * modexp(v, u, N), b, N)
  _K = sha256_hexdigest(_S.to_s.bytes)
  assert(sha256_hmac(_K.bytes, salt.to_s.bytes) == hmac)
  password
end

if ROLE == 'C'
  email = "#{random_word}@example.com"
  password = random_word
  signup_client(email, password)
  login_client(email, password)
  login_client(email, password)
else
  credentials = {}
  _I, salt, v = signup_server
  credentials[_I] = [salt, v]
  login_server(credentials)
  bad_login_server(credentials)
end
