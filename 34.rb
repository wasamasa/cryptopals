## Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

# Use the code you just worked out to build a protocol and an "echo"
# bot. You don't actually have to do the network part of this if you
# don't want; just simulate that. The protocol is:
#
# A->B
#     Send "p", "g", "A"
# B->A
#     Send "B"
# A->B
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
# B->A
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
#
# (In other words, derive an AES key from DH with SHA1, use it in both
# directions, and do CBC with random IVs appended or prepended to the
# message).
#
# Now implement the following MITM attack:
#
# A->M
#     Send "p", "g", "A"
# M->B
#     Send "p", "g", "p"
# B->M
#     Send "B"
# M->A
#     Send "p"
# A->M
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), msg) + iv
# M->B
#     Relay that to B
# B->M
#     Send AES-CBC(SHA1(s)[0:16], iv=random(16), A's msg) + iv
# M->A
#     Relay that to A
#
# M should be able to decrypt the messages. "A" and "B" in the
# protocol --- the public keys, over the wire --- have been swapped
# out with "p". Do the DH math on this quickly to see what that does
# to the predictability of the key.
#
# Decrypt the messages from M's vantage point as they go by.
#
# Note that you don't actually have to inject bogus parameters to make
# this attack work; you could just generate Ma, MA, Mb, and MB as
# valid DH parameters to do a generic MITM attack. But do the
# parameter injection attack; it's going to come up again.

require_relative 'util'

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
  send(M, "#{p} #{g} #{_A}")
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
  p, g, _A = recv(B).split(' ').map(&:to_i)
  b, _B = generate_dh_keys(p, g)
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
  p, g, _A = recv(M).split(' ').map(&:to_i)
  send(B, "#{p} #{g} #{p}")
  _B = recv(M).to_i
  send(A, p.to_s)
  s = 0
  key = make_sha1_key(s)
  msg = recv(M)
  send(B, msg)
  ciphertext, iv = msg.split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, iv, key))
  info("intercepted message: #{str(message)}")
  msg = recv(M)
  send(A, msg)
  ciphertext, iv = msg.split(' ').map { |str| b64decode(str) }
  message = pkcs7unpad(aes_cbc_decrypt(ciphertext, iv, key))
  info("intercepted message: #{str(message)}")
end

# the shared secret ends up being 0, why is that so?

# A = p, B = p
# s = B ** a % p = p ** a % p = 0
# s = A ** b % p = p ** b % p = 0
