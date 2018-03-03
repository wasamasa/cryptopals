## Bleichenbacher's e=3 RSA Attack

## Crypto-tourism informational placard.

# This attack broke Firefox's TLS certificate validation several years
# ago. You could write a Python script to fake an RSA signature for
# any certificate. We find new instances of it every other year or so.

# RSA with an encrypting exponent of 3 is popular, because it makes
# the RSA math faster.
#
# With e=3 RSA, encryption is just cubing a number mod the public
# encryption modulus:
#
#     c = m ** 3 % n
#
# e=3 is secure as long as we can make assumptions about the message
# blocks we're encrypting. The worry with low-exponent RSA is that the
# message blocks we process won't be large enough to wrap the modulus
# after being cubed. The block 00:02 (imagine sufficient zero-padding)
# can be "encrypted" in e=3 RSA; it is simply 00:08.
#
# When RSA is used to sign, rather than encrypt, the operations are
# reversed; the verifier "decrypts" the message by cubing it. This
# produces a "plaintext" which the verifier checks for validity.
#
# When you use RSA to sign a message, you supply it a block input that
# contains a message digest. The PKCS1.5 standard formats that block
# as:
#
#     00h 01h ffh ffh ... ffh ffh 00h ASN.1 GOOP HASH
#
# As intended, the ffh bytes in that block expand to fill the whole
# block, producing a "right-justified" hash (the last byte of the hash
# is the last byte of the message).
#
# There was, 7 years ago, a common implementation flaw with RSA
# verifiers: they'd verify signatures by "decrypting" them (cubing
# them modulo the public exponent) and then "parsing" them by looking
# for 00h 01h ... ffh 00h ASN.1 HASH.
#
# This is a bug because it implies the verifier isn't checking all the
# padding. If you don't check the padding, you leave open the
# possibility that instead of hundreds of ffh bytes, you have only a
# few, which if you think about it means there could be squizzilions
# of possible numbers that could produce a valid-looking signature.
#
# How to find such a block? Find a number that when cubed (a) doesn't
# wrap the modulus (thus bypassing the key entirely) and (b) produces
# a block that starts "00h 01h ffh ... 00h ASN.1 HASH".
#
# There are two ways to approach this problem:
#
# - You can work from Hal Finney's writeup, available on Google, of
#   how Bleichenbacher explained the math "so that you can do it by
#   hand with a pencil".
# - You can implement an integer cube root in your language, format
#   the message block you want to forge, leaving sufficient trailing
#   zeros at the end to fill with garbage, then take the cube-root of
#   that block.
#
# Forge a 1024-bit RSA signature for the string "hi mom". Make sure
# your implementation actually accepts the signature!

require_relative 'util'
require_relative 'sha1'

MESSAGE = 'hi mom'.bytes
PUBLIC, PRIVATE = make_rsa_keys(generate_prime(512), generate_prime(512))
MODULUS_SIZE = 1024
# we'll use md5 here because it makes for the smallest padding
# see https://tools.ietf.org/html/rfc3447#section-9.2
ASN1_PREFIX = [0x30, 0x20, 0x30, 0x0c, 0x06, 0x08, 0x2a, 0x86, 0x48,
               0x86, 0xf7, 0x0d, 0x02, 0x05, 0x05, 0x00, 0x04].freeze
HASH_SIZE = 16
MAX_GARBAGE_SIZE = MODULUS_SIZE / 8 - ASN1_PREFIX.size - HASH_SIZE - 4

def pkcs1_v15_pad(buffer, modulus_size, garbage = [])
  hash = hexdecode(md5_hexdigest(buffer))
  prefix = [0x00, 0x01]
  suffix = [0x00] + ASN1_PREFIX + hash + garbage
  padding_size = modulus_size / 8 - prefix.size - suffix.size
  raise 'message too long' if padding_size < 1
  padding = Array.new(padding_size, 0xff)
  prefix + padding + suffix
end

def bad_pkcs1_v15_unpad(buffer, modulus_size)
  buffer = leftpad(buffer, modulus_size / 8)
  assert(buffer[0..1] == [0x00, 0x01])
  assert(buffer[2] == 0xff)
  rest = buffer.drop(2).drop_while { |b| b == 0xff }
  assert(rest[0] = 0x00)
  assert(rest[1..ASN1_PREFIX.size] == ASN1_PREFIX)
  hash = rest.drop(ASN1_PREFIX.size + 1).take(HASH_SIZE)
  assert(hash.size == HASH_SIZE)
  hash
end

def rsa_sign(buffer, private_key, garbage = [])
  m = buffer_to_number(pkcs1_v15_pad(buffer, MODULUS_SIZE, garbage))
  d, n = private_key
  modexp(m, d, n)
end

def rsa_verify(buffer, signature, public_key)
  e, n = public_key
  m = modexp(signature, e, n)
  message_hash = bad_pkcs1_v15_unpad(number_to_buffer(m), MODULUS_SIZE)
  md5_hexdigest(buffer) == hexencode(message_hash)
end

assert(rsa_verify(MESSAGE, rsa_sign(MESSAGE, PRIVATE), PUBLIC))
assert(rsa_verify(MESSAGE, rsa_sign(MESSAGE, PRIVATE, [1, 2, 3]), PUBLIC))
garbage = Array.new(MAX_GARBAGE_SIZE, 0x00)
assert(rsa_verify(MESSAGE, rsa_sign(MESSAGE, PRIVATE, garbage), PUBLIC))

message_block = pkcs1_v15_pad(MESSAGE, MODULUS_SIZE, garbage)
bad_signature = icbrt(buffer_to_number(message_block), true)
assert(rsa_verify(MESSAGE, bad_signature, PUBLIC))
