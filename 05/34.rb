require_relative '../util'

ROLE = ENV['ROLE'] || 'A'
A = '/tmp/cryptopals-34-A'.freeze
B = '/tmp/cryptopals-34-B'.freeze
M = '/tmp/cryptopals-34-M'.freeze
MESSAGE = b64decode('Qy1DeXBoZXItUHVua3MgY291bGRuJ3QgaG9sZCB1cw==')

assert(%w(A B M).include?(ROLE))

ensure_pipe(A)
ensure_pipe(B)
ensure_pipe(M)

if ROLE == 'A'
  p = 37
  g = 5
  a, _A = generate_dh_keys(p, g)
  snd(M, "#{p} #{g} #{_A}")
  _B = rcv(A).to_i
  s = modexp(_B, a, p)
  info("shared secret: #{s}")
  key = make_sha1_key(s)
  iv = random_bytes(16)
  ciphertext = aes_cbc_encrypt(pkcs7pad(MESSAGE, 16), key, iv)
  snd(M, "#{b64encode(ciphertext)} #{b64encode(iv)}")
  info("sent message: #{str(MESSAGE)}")
  ciphertext, iv = rcv(A).split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, key, iv))
  info("received message: #{str(message)}")
  assert(MESSAGE == message)
  info('roundtrip successful')
elsif ROLE == 'B'
  p, g, _A = rcv(B).split(' ').map(&:to_i)
  b, _B = generate_dh_keys(p, g)
  snd(M, _B.to_s)
  s = modexp(_A, b, p)
  info("shared secret: #{s}")
  key = make_sha1_key(s)
  ciphertext, iv = rcv(B).split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, key, iv))
  info("received message: #{str(message)}")
  iv = random_bytes(16)
  ciphertext = aes_cbc_encrypt(pkcs7pad(message, 16), key, iv)
  snd(M, "#{b64encode(ciphertext)} #{b64encode(iv)}")
  info("resent message: #{str(message)}")
else
  p, g, _A = rcv(M).split(' ').map(&:to_i)
  snd(B, "#{p} #{g} #{p}")
  _B = rcv(M).to_i
  snd(A, p.to_s)
  s = 0
  key = make_sha1_key(s)
  msg = rcv(M)
  snd(B, msg)
  ciphertext, iv = msg.split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, key, iv))
  info("intercepted message: #{str(message)}")
  msg = rcv(M)
  snd(A, msg)
  ciphertext, iv = msg.split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, key, iv))
  info("intercepted message: #{str(message)}")
end

# the shared secret ends up being 0, why is that so?

# A = p, B = p
# s = B ** a % p = p ** a % p = 0
# s = A ** b % p = p ** b % p = 0
