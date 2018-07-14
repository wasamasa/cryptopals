require_relative '../util'

assert(pkcs7pad('123'.bytes, 4) == "123\x01".bytes)
assert(pkcs7pad('1234'.bytes, 4) == "1234\x04\x04\x04\x04".bytes)
assert(pkcs7pad('12345'.bytes, 4) == "12345\x03\x03\x03".bytes)
assert(pkcs7pad('YELLOW SUBMARINE'.bytes, 20) == "YELLOW SUBMARINE\x04\x04\x04\x04".bytes)
