require_relative '../util'

assert(pkcs7unpad("ICE ICE BABY\x04\x04\x04\x04".bytes))
assert_error { pkcs7unpad("ICE ICE BABY\x05\x05\x05\x05".bytes) }
assert_error { pkcs7unpad("ICE ICE BABY\x01\x02\x03\x04".bytes) }
