require_relative '../util'
require_relative '../sha1'

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
  buffer = leftpad(buffer, modulus_size / 8, 0)
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
bad_signature = icbrt(buffer_to_number(message_block))
assert(rsa_verify(MESSAGE, bad_signature, PUBLIC))
