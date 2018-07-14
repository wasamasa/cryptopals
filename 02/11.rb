require_relative '../util'

def encryption_oracle(input)
  key = random_bytes(16)
  prefix = random_bytes(rand(5..10))
  suffix = random_bytes(rand(5..10))
  input = pkcs7pad(prefix + input + suffix, 16)
  if rand(2).zero?
    info('Encrypting with ECB...')
    aes_ecb_encrypt(input, key)
  else
    iv = random_bytes(16)
    info('Encrypting with CBC...')
    aes_cbc_encrypt(input, key, iv)
  end
end

def detect_cipher_mode
  input = Array.new(50, 'A'.ord)
  output = encryption_oracle(input)
  if find_duplicate(output.each_slice(16).to_a)
    info('Detected ECB')
  else
    info('Detected CBC')
  end
end

10.times { detect_cipher_mode }
