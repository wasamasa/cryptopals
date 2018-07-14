require_relative '../util'

ROLE = ENV['ROLE'] || 'A'
A = '/tmp/cryptopals-35-A'.freeze
B = '/tmp/cryptopals-35-B'.freeze
M = '/tmp/cryptopals-35-M'.freeze
STRATEGY = ENV['STRATEGY'] || '1'
MESSAGE = b64decode('Tm93IHRoYXQncyBhIGNhbGN1bGF0ZWQgbWlzdGFrZQ==')

assert(%w(A B M).include?(ROLE))
assert(%w(1 P P_1).include?(STRATEGY))

ensure_pipe(A)
ensure_pipe(B)
ensure_pipe(M)

if ROLE == 'A'
  p = 37
  g = 5
  snd(M, "#{p} #{g}")
  assert(rcv(A) == 'ACK')
  info('received ack')
  a, _A = generate_dh_keys(p, g)
  snd(M, _A.to_s)
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
  p, g = rcv(B).split(' ').map(&:to_i)
  snd(M, 'ACK')
  info('sent ack')
  b, _B = generate_dh_keys(p, g)
  _A = rcv(B).to_i
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
  msg = rcv(M)
  p = msg.split(' ')[0].to_i
  case STRATEGY
  when '1'
    g = 1
    s = 1
  when 'P'
    g = p
    s = 0
  when 'P_1'
    g = p - 1
  end
  snd(B, "#{p} #{g}")
  msg = rcv(M)
  snd(A, msg)
  _A = rcv(M).to_i
  snd(B, _A.to_s)
  _B = rcv(M).to_i
  snd(A, _B.to_s)
  msg = rcv(M)
  snd(B, msg)
  info("variables: #{[p, g, _A, _B]}")
  ciphertext, iv = msg.split(' ').map { |str| b64decode(str) }
  if STRATEGY == 'P_1'
    begin
      key = make_sha1_key(1)
      message = pkcs7unpad(aes_cbc_decrypt(ciphertext, key, iv))
    rescue StandardError
      key = make_sha1_key(g)
      message = pkcs7unpad(aes_cbc_decrypt(ciphertext, key, iv))
    end
  else
    key = make_sha1_key(s)
    message = pkcs7unpad(aes_cbc_decrypt(ciphertext, key, iv))
  end
  info("intercepted message: #{str(message)}")
  # in the rare case A and B share the same secret, this makes sure
  # the conversation is terminated
  msg = rcv(M)
  snd(A, msg)
end

# the reason this isn't terribly real-world is because in most cases A
# calculates a different shared secret from B if g is being tampered
# with, so A can successfully send a message, but B can't decrypt it
# (however M will have the message by then and can decrypt it)

# g = 1
# B = 1**b % p = 1**b % p = 1 % p = 1
# s = B**a % p = 1**a % p = 1 % p = 1

# g = p
# B = p**b % p = p**b % p = 0
# s = B**a % p = 0**a % p = 0 % p = 0

# g = p - 1
# B = (p - 1)**b % p # either 1 if b is even or p - 1 if b is odd
# s = B**a % p # either 1 if B is 1 or 1 if a is even or p - 1 if a is odd
