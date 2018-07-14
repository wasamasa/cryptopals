require_relative '../util'

KEY = random_bytes(16)
IV = random_bytes(16)

# this CBC feature seems to be about error recovery/tolerance, if
# corruption has been detected, one could retransmit the two faulty
# blocks and keep the remaining ones

def encode_cookie(userdata)
  prefix = 'comment1=cooking%20MCs;userdata='
  suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
  input = prefix + userdata.tr(';=', '') + suffix
  aes_cbc_encrypt(pkcs7pad(input.bytes, 16), KEY, IV)
end

def decode_cookie(buffer)
  input = str(pkcs7unpad(aes_cbc_decrypt(buffer, KEY, IV)))
  info("Decoded string: #{input}")
  output = input.split(';').map { |kv| kv.split('=') }.to_h
  info("Decoded data: #{output}")
  assert(output['admin'] == 'true')
end

# ('<'.ord^1).chr #=> '='
# (':'.ord^1).chr #=> ';'
input = 'AAAAAAAAAAAAAAAA:admin<true:A<AA'
cookie = encode_cookie(input)
cookie[32] ^= 1
cookie[38] ^= 1
cookie[43] ^= 1
cookie[45] ^= 1
decode_cookie(cookie)
