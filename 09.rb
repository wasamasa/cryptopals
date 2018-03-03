## Implement PKCS#7 padding

# A block cipher transforms a fixed-sized block (usually 8 or 16
# bytes) of plaintext into ciphertext. But we almost never want to
# transform a single block; we encrypt irregularly-sized messages.
#
# One way we account for irregularly-sized messages is by padding,
# creating a plaintext that is an even multiple of the blocksize. The
# most popular padding scheme is called PKCS#7.
#
# So: pad any block to a specific block length, by appending the
# number of bytes of padding to the end of the block. For instance,
#
#     "YELLOW SUBMARINE"
#
# ... padded to 20 bytes would be:
#
#     "YELLOW SUBMARINE\x04\x04\x04\x04"

require_relative 'util'

assert(pkcs7pad('123'.bytes, 4) == "123\x01".bytes)
assert(pkcs7pad('1234'.bytes, 4) == "1234\x04\x04\x04\x04".bytes)
assert(pkcs7pad('12345'.bytes, 4) == "12345\x03\x03\x03".bytes)
assert(pkcs7pad('YELLOW SUBMARINE'.bytes, 20) == "YELLOW SUBMARINE\x04\x04\x04\x04".bytes)
