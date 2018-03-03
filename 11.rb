## An ECB/CBC detection oracle

# Now that you have ECB and CBC working:
#
# Write a function to generate a random AES key; that's just 16 random
# bytes.
#
# Write a function that encrypts data under an unknown key --- that
# is, a function that generates a random key and encrypts under it.
#
# The function should look like:
#
#     encryption_oracle(your-input)
#     => [MEANINGLESS JIBBER JABBER]
#
# Under the hood, have the function *append* 5-10 bytes (count chosen
# randomly) *before* the plaintext and 5-10 bytes *after* the
# plaintext.
#
# Now, have the function choose to encrypt under ECB 1/2 the time, and
# under CBC the other half (just use random IVs each time for
# CBC). Use rand(2) to decide which to use.
#
# Detect the block cipher mode the function is using each time. You
# should end up with a piece of code that, pointed at a block box that
# might be encrypting ECB or CBC, tells you which one is happening.

require_relative 'util'

def encryption_oracle(input)
  key = str(random_bytes(16))
  prefix = random_bytes(rand(5..10))
  suffix = random_bytes(rand(5..10))
  input = pkcs7pad(prefix + input + suffix, 16)
  if rand(2).zero?
    info('Encrypting with ECB...')
    aes_ecb_encrypt(input, key)
  else
    iv = random_bytes(16)
    info('Encrypting with CBC...')
    aes_cbc_encrypt(input, iv, key)
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
