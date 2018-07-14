require_relative '../util'

ROLE = ENV['ROLE'] || 'C'
C = '/tmp/cryptopals-37-C'.freeze
S = '/tmp/cryptopals-37-S'.freeze
NIST_PRIME = 0xffffffffffffffffc90fdaa22168c234c4c6628b80dc1cd129024e088a67cc74020bbea63b139b22514a08798e3404ddef9519b3cd3a431b302b0a6df25f14374fe1356d6d51c245e485b576625e7ec6f44c42e9a637ed6b0bff5cb6f406b7edee386bfb5a899fa5ae9f24117c4b1fe649286651ece45b3dc2007cb8a163bf0598da48361c55d39a69163fa8fd24cf5f83655d23dca3ad961c62f356208552bb9ed529077096966d670c354e4abc9804f1746c08ca237327ffffffffffffffff

assert(%w(C S).include?(ROLE))

ensure_pipe(C)
ensure_pipe(S)

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
  info("signup from #{_I}")
  [_I, salt.to_i, v.to_i]
end

def login_client(email, password)
  g = 2
  k = 3
  a = rand(1..1024)
  _A = modexp(g, a, N)
  snd(S, "#{email} #{_A}")
  salt, _B = rcv(C).split(' ').map(&:to_i)
  u = sha256_hexdigest("#{_A}#{_B}".bytes).to_i(16)
  x = sha256_hexdigest("#{salt}#{password}".bytes).to_i(16)
  _S = modexp(_B - k * modexp(g, x, N), a + u * x, N)
  _K = sha256_hexdigest(_S.to_s.bytes)
  snd(S, sha256_hmac(_K.bytes, salt.to_s.bytes))
  assert(rcv(C) == 'OK')
  info('login successful!')
end

def bad_login_client(email, _A)
  snd(S, "#{email} #{_A}")
  salt = rcv(C).split(' ')[0]
  _S = 0
  _K = sha256_hexdigest(_S.to_s.bytes)
  snd(S, sha256_hmac(_K.bytes, salt.to_s.bytes))
  assert(rcv(C) == 'OK')
  info('login successful!')
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
  info('login successful!')
end

if ROLE == 'C'
  email = "#{random_word}@example.com"
  password = random_word
  signup_client(email, password)
  login_client(email, password)
  bad_login_client(email, 0)
  bad_login_client(email, N)
  bad_login_client(email, N * 2)
  bad_login_client(email, N * 3)
else
  credentials = {}
  _I, salt, v = signup_server
  credentials[_I] = [salt, v]
  login_server(credentials)
  login_server(credentials)
  login_server(credentials)
  login_server(credentials)
  login_server(credentials)
end
