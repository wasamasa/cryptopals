require_relative '../util'

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
