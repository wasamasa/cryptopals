## CTR bitflipping

# There are people in the world that believe that CTR resists bit
# flipping attacks of the kind to which CBC mode is susceptible.
#
# Re-implement the CBC bitflipping exercise from earlier (#16) to use
# CTR mode instead of CBC mode. Inject an "admin=true" token.

require_relative 'util'

NONCE = 42
KEY = random_bytes(16)

def encode_cookie(userdata)
  prefix = 'comment1=cooking%20MCs;userdata='
  suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
  input = prefix + userdata.tr(';=', '') + suffix
  aes_ctr_encrypt(input.bytes, KEY, NONCE)
end

def decode_cookie(buffer)
  input = str(aes_ctr_decrypt(buffer, KEY, NONCE))
  info("decoded string: #{input}")
  output = input.split(';').map { |kv| kv.split('=') }.to_h
  info("decoded data: #{output}")
  assert(output['admin'] == 'true')
end

# ('<'.ord^1).chr #=> '='
# (':'.ord^1).chr #=> ';'
input = 'AAAA:admin<true'
cookie = encode_cookie(input)
cookie[36] ^= 1
cookie[42] ^= 1
decode_cookie(cookie)
