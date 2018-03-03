## Implement RSA

# There are two annoying things about implementing RSA. Both of them
# involve key generation; the actual encryption/decryption in RSA is
# trivial.
#
# First, you need to generate random primes. You can't just agree on a
# prime ahead of time, like you do in DH. You can write this algorithm
# yourself, but I just cheat and use OpenSSL's BN library to do the
# work.
#
# The second is that you need an "invmod" operation (the
# multiplicative inverse), which is not an operation that is wired
# into your language. The algorithm is just a couple lines, but I
# always lose an hour getting it to work.
#
# I recommend you not bother with primegen, but do take the time to
# get your own EGCD and invmod algorithm working.
#
# Now:
#
# - Generate 2 random primes. We'll use small numbers to start, so you
#   can just pick them out of a prime table. Call them "p" and "q".
# - Let n be p * q. Your RSA math is modulo n.
# - Let et be (p-1)*(q-1) (the "totient"). You need this value only
#   for keygen.
# - Let e be 3.
# - Compute d = invmod(e, et). invmod(17, 3120) is 2753.
# - Your public key is [e, n]. Your private key is [d, n].
# - To encrypt: c = m**e%n. To decrypt: m = c**d%n
# - Test this out with a number, like "42".
# - Repeat with bignum primes (keep e=3).
#
# Finally, to encrypt a string, do something cheesy, like convert the
# string to hex and put "0x" on the front of it to turn it into a
# number. The math cares not how stupidly you feed it strings.

require_relative 'util'

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
