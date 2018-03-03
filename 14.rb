## Byte-at-a-time ECB decryption (Harder)

# Take your oracle function from #12. Now generate a random count of
# random bytes and prepend this string to every plaintext. You are now
# doing:
#
#     AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
#
# Same goal: decrypt the target-bytes.

## Stop and think for a second.

# What's harder than challenge #12 about doing this? How would you
# overcome that obstacle? The hint is: you're using all the tools you
# already have; no crazy math is required.
#
# Think "STIMULUS" and "RESPONSE".

require_relative 'util'

KEY = str(random_bytes(16))
PREFIX = random_bytes(rand(2..40))
UNKNOWN = b64decode('Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK')
BLOCKSIZE = 16
A = 'A'.ord

def encryption_oracle(input)
  aes_ecb_encrypt(pkcs7pad(PREFIX + input + UNKNOWN, BLOCKSIZE), KEY)
end

# XXXXXXXAAAAAAAAA|AAAAAAAAAAAAAAAA|AAAAAAAAAAAAAAAA|YYYYYYYYYYYYYYYY
# prefix: 7, junk: 9, duplicate at: 1

# XXXXXXXXXXXXXXXX|XXXAAAAAAAAAAAAA|AAAAAAAAAAAAAAAA|AAAAAAAAAAAAAAAA|YYYYYYYYYYYYYYYY|YYYYYYYYYYYYYZZZ
# prefix: 19, junk: 13, duplicate at: 2

def find_prefix_length
  glue = Array.new(32, A)
  duplicate_index = nil
  loop do
    output = encryption_oracle(glue)
    blocks = output.each_slice(BLOCKSIZE).to_a
    duplicate_index = blocks.index(find_duplicate(blocks))
    break if duplicate_index
    glue << A
  end
  (duplicate_index + 2) * BLOCKSIZE - glue.length
end

# XXXXXXXXAAAAAAAA|AAAAAAAAAAAAAAAY|YYYYYYYYYYYYYYYY
#   ^        ^    ^
# prefix    glue  |
#      cutoff ----'

def find_matching_byte(input, target, cutoff, size)
  (0..255).each do |byte|
    output = encryption_oracle(input + [byte])
    return byte if output.slice(cutoff, size) == target
  end
end

def decrypt_byte(prefix_length, known)
  glue_length = BLOCKSIZE - prefix_length % BLOCKSIZE
  glue = Array.new(glue_length, A)
  size = (known.length / BLOCKSIZE + 1) * BLOCKSIZE
  prefix = Array.new(size - known.length - 1, A)
  cutoff = glue_length + prefix_length
  target = encryption_oracle(glue + prefix).slice(cutoff, size)
  find_matching_byte(glue + prefix + known, target, cutoff, size)
end

prefix_length = find_prefix_length
info("Prefix length: #{prefix_length}")
info("Actual prefix length: #{PREFIX.length}")

known = []
UNKNOWN.length.times { known << decrypt_byte(prefix_length, known) }

puts str(known)
