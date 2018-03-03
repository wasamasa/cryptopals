## Byte-at-a-time ECB decryption (Simple)

# Copy your oracle function to a new function that encrypts buffers
# under ECB mode using a consistent but unknown key (for instance,
# assign a single random key, once, to a global variable).
#
# Now take that same function and have it append to the plaintext,
# BEFORE ENCRYPTING, the following string:
#
#     Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
#     aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
#     dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
#     YnkK

## Spoiler alert.

# Do not decode this string now. Don't do it.

# Base64 decode the string before appending it. *Do not base64 decode
# the string by hand; make your code do it.* The point is that you
# don't know its contents.
#
# What you have now is a function that produces:
#
#     AES-128-ECB(your-string || unknown-string, random-key)
#
# It turns out: you can decrypt "unknown-string" with repeated calls
# to the oracle function!
#
# Here's roughly how:
#
# 1. Feed identical bytes of your-string to the function 1 at a time
# --- start with 1 byte ("A"), then "AA", then "AAA" and so
# on. Discover the block size of the cipher. You know it, but do this
# step anyway.
#
# 2. Detect that the function is using ECB. You already know, but do
# this step anyways.
#
# 3. Knowing the block size, craft an input block that is exactly 1
# byte short (for instance, if the block size is 8 bytes, make
# "AAAAAAA"). Think about what the oracle function is going to put in
# that last byte position.
#
# 4. Make a dictionary of every possible last byte by feeding
# different strings to the oracle; for instance, "AAAAAAAA",
# "AAAAAAAB", "AAAAAAAC", remembering the first block of each
# invocation.
#
# 5. Match the output of the one-byte-short input to one of the
# entries in your dictionary. You've now discovered the first byte of
# unknown-string.
#
# 6. Repeat for the next byte.

## Congratulations.

# This is the first challenge we've given you whose solution will
# break real crypto. Lots of people know that when you encrypt
# something in ECB mode, you can see penguins through it. Not so many
# of them can decrypt the contents of those ciphertexts, and now you
# can. If our experience is any guideline, this attack will get you
# code execution in security tests about once a year.

require_relative 'util'

KEY = str(random_bytes(16))
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
