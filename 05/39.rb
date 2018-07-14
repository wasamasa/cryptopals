require_relative '../util'

assert(invmod(17, 3120) == 2753)
MESSAGE = b64decode('TWlkbmlnaHQgaW4gYSBQZXJmZWN0IFdvcmxk')

def test_rsa(p, q, message)
  public_key, private_key = make_rsa_keys(p, q, 3)
  c = rsa_encrypt(message, public_key)
  msg = rsa_decrypt(c, private_key)
  assert(message == msg)
  info(str(msg))
end

test_rsa(generate_prime, generate_prime, MESSAGE)
