require_relative '../util'

KEY = random_bytes(16)
UNKNOWN = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
A = 'A'.ord

def encryption_oracle(input)
  aes_ecb_encrypt(pkcs7pad(input + UNKNOWN, 16), KEY)
end

def detect_blocksize
  last = encryption_oracle(Array.new(1, A))
  count = 1
  loop do
    output = encryption_oracle(Array.new(count + 1, A))
    break if output.slice(0, count) == last.slice(0, count)
    last = output
    count += 1
  end
  count
end

def ecb?(blocksize)
  output = encryption_oracle(Array.new(3 * blocksize, A))
  output.slice(0, blocksize) == output.slice(blocksize, blocksize)
end

def find_matching_byte(input, target, size)
  (0..255).each do |byte|
    output = encryption_oracle(input + [byte])
    return byte if output.slice(0, size) == target
  end
end

def decrypt_byte(known, blocksize)
  size = (known.length / blocksize + 1) * blocksize
  prefix = Array.new(size - known.length - 1, A)
  target = encryption_oracle(prefix).slice(0, size)
  find_matching_byte(prefix + known, target, size)
end

blocksize = detect_blocksize
info("Blocksize: #{blocksize}")
info("ECB mode: #{ecb?(blocksize)}")

known = []
UNKNOWN.length.times { known << decrypt_byte(known, blocksize) }

puts str(known)
