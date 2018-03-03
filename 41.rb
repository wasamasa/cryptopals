## Implement unpadded message recovery oracle

# Nate Lawson says we should stop calling it "RSA padding" and start
# calling it "RSA armoring". Here's why.
#
# Imagine a web application, again with the Javascript encryption,
# taking RSA-encrypted messages which (again: Javascript) aren't
# padded before encryption at all.
#
# You can submit an arbitrary RSA blob and the server will return
# plaintext. But you can't submit the same message twice: let's say
# the server keeps hashes of previous messages for some liveness
# interval, and that the message has an embedded timestamp:
#
#     {
#       time: 1356304276,
#       social: '555-55-5555',
#     }
#
# You'd like to capture other people's messages and use the server to
# decrypt them. But when you try, the server takes the hash of the
# ciphertext and uses it to reject the request. Any bit you flip in
# the ciphertext irrevocably scrambles the decryption.
#
# This turns out to be trivially breakable:
#
# - Capture the ciphertext C
# - Let N and E be the public modulus and exponent respectively
# - Let S be a random number > 1 mod N. Doesn't matter what.
# - Now:
#       C' = ((S**E mod N) C) mod N
# - Submit C', which appears totally different from C, to the server,
#   recovering P', which appears totally different from P
# - Now:
#             P'
#       P = -----  mod N
#             S
#
# Oops!
#
# Implement that attack.

## Careful about division in cyclic groups.

# Remember: you don't simply divide mod N; you multiply by the
# multiplicative inverse mod N. So you'll need a modinv() function.

require_relative 'util'

# it should be C' = ((S**E mod N) * C) mod N

class Server
  def initialize
    @p = generate_prime(512)
    @q = generate_prime(512)
    @e = 17
    @private_key, @public_key = make_rsa_keys(@p, @q, @e)
    @seen_messages = {}
  end

  attr_reader :public_key

  def catch_message
    buffer = random_message.bytes
    c = rsa_encrypt(buffer, @public_key)
    hash = sha256_hexdigest(c.to_s.bytes)
    @seen_messages[hash] = true
    c
  end

  def decrypt_message(c)
    hash = sha256_hexdigest(c.to_s.bytes)
    raise 'seems familiar' if @seen_messages.include?(hash)
    @seen_messages[hash] = true
    rsa_decrypt(c, @private_key)
  end

  private

  def random_message
    timestamp = Time.now.to_i
    id = format('%d%d%d-%d%d-%d%d%d%d',
                random_digit, random_digit, random_digit,
                random_digit, random_digit,
                random_digit, random_digit, random_digit, random_digit)
    "{\n  time: #{timestamp},\n  social: '#{id}',\n}"
  end
end

server = Server.new
message = server.catch_message
assert(!ignore_errors { server.decrypt_message(message) })

C = server.catch_message
E, N = server.public_key
S = 2 # no need to use a random one
C_ = (modexp(S, E, N) * C) % N # equivalent to (S * C) % N
P_ = buffer_to_number(server.decrypt_message(C_))
P = (P_ * invmod(S, N)) % N # equivalent to (P_ / S) % N
info(str(number_to_buffer(P)))
