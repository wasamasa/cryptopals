## Implement DH with negotiated groups, and break with malicious "g" parameters

# A->B
#     Send "p", "g"
# B->A
#     Send ACK
# A->B
#     Send "A"
# B->A
#     Send "B"
# A->B
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
# B->A
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
#
# Do the MITM attack again, but play with "g". What happens with:
#
#     g = 1
#     g = p
#     g = p - 1
#
# Write attacks for each.

## When does this ever happen?

# Honestly, not that often in real-world systems. If you can mess with
# "g", chances are you can mess with something worse. Most systems
# pre-agree on a static DH group. But the same construction exists in
# Elliptic Curve Diffie-Hellman, and this becomes more relevant there.

require_relative 'util'

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
  send(M, "#{p} #{g}")
  assert(recv(A) == 'ACK')
  info('received ack')
  a, _A = generate_dh_keys(p, g)
  send(M, _A.to_s)
  _B = recv(A).to_i
  s = modexp(_B, a, p)
  info("shared secret: #{s}")
  key = make_sha1_key(s)
  iv = random_bytes(16)
  ciphertext = aes_cbc_encrypt(pkcs7pad(MESSAGE, 16), iv, key)
  send(M, "#{b64encode(ciphertext)} #{b64encode(iv)}")
  info("sent message: #{str(MESSAGE)}")
  ciphertext, iv = recv(A).split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, iv, key))
  info("received message: #{str(message)}")
  assert(MESSAGE == message)
  info('roundtrip successful')
elsif ROLE == 'B'
  p, g = recv(B).split(' ').map(&:to_i)
  send(M, 'ACK')
  info('sent ack')
  b, _B = generate_dh_keys(p, g)
  _A = recv(B).to_i
  send(M, _B.to_s)
  s = modexp(_A, b, p)
  info("shared secret: #{s}")
  key = make_sha1_key(s)
  ciphertext, iv = recv(B).split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, iv, key))
  info("received message: #{str(message)}")
  iv = random_bytes(16)
  ciphertext = aes_cbc_encrypt(pkcs7pad(message, 16), iv, key)
  send(M, "#{b64encode(ciphertext)} #{b64encode(iv)}")
  info("resent message: #{str(message)}")
else
  msg = recv(M)
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
  send(B, "#{p} #{g}")
  msg = recv(M)
  send(A, msg)
  _A = recv(M).to_i
  send(B, _A.to_s)
  _B = recv(M).to_i
  send(A, _B.to_s)
  msg = recv(M)
  send(B, msg)
  info("variables: #{[p, g, _A, _B]}")
  ciphertext, iv = msg.split(' ').map { |str| b64decode(str) }
  if STRATEGY == 'P_1'
    begin
      key = make_sha1_key(1)
      message = pkcs7unpad(aes_cbc_decrypt(ciphertext, iv, key))
    rescue StandardError
      key = make_sha1_key(g)
      message = pkcs7unpad(aes_cbc_decrypt(ciphertext, iv, key))
    end
  else
    key = make_sha1_key(s)
    message = pkcs7unpad(aes_cbc_decrypt(ciphertext, iv, key))
  end
  info("intercepted message: #{str(message)}")
  # in the rare case A and B share the same secret, this makes sure
  # the conversation is terminated
  msg = recv(M)
  send(A, msg)
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
