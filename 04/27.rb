require_relative '../util'

IV = random_bytes(16)
KEY = IV

def encode_cookie(userdata)
  prefix = 'comment1=cooking%20MCs;userdata='
  suffix = ';comment2=%20like%20a%20pound%20of%20bacon'
  input = prefix + userdata.tr(';=', '') + suffix
  raise "invalid ASCII string: #{input}" unless input.ascii_only?
  aes_cbc_encrypt(pkcs7pad(input.bytes, 16), KEY, IV)
end

def decode_cookie(buffer)
  input = str(pkcs7unpad(aes_cbc_decrypt(buffer, KEY, IV)))
  raise "invalid ASCII string: #{input}" unless input.ascii_only?
  output = input.split(';').map { |kv| kv.split('=') }.to_h
  assert(output['admin'] == 'true')
end

def get_error_string
  input = 'A' * (16 * 3)
  cookie = encode_cookie(input)
  16.times { |i| cookie[16 + i] = 0 }
  16.times { |i| cookie[32 + i] = cookie[i] }
  begin
    decode_cookie(cookie)
  rescue RuntimeError => e
    assert(e.message.start_with?('invalid ASCII string:'))
    e.message.slice(22..-1)
  end
end

blocks = get_error_string.bytes.each_slice(16).take(3)
key = xor_buffers(blocks[0], blocks[2])
assert(key == KEY)
