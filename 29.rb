## Break a SHA-1 keyed MAC using length extension

# Secret-prefix SHA-1 MACs are trivially breakable.
#
# The attack on secret-prefix SHA1 relies on the fact that you can
# take the ouput of SHA-1 and use it as a new starting point for
# SHA-1, thus taking an arbitrary SHA-1 hash and "feeding it more
# data".
#
# Since the key precedes the data in secret-prefix, any additional
# data you feed the SHA-1 hash in this fashion will appear to have
# been hashed with the secret key.
#
# To carry out the attack, you'll need to account for the fact that
# SHA-1 is "padded" with the bit-length of the message; your forged
# message will need to include that padding. We call this "glue
# padding". The final message you actually forge will be:
#
#     SHA1(key || original-message || glue-padding || new-message)
#
# (where the final padding on the whole constructed message is
# implied)
#
# Note that to generate the glue padding, you'll need to know the
# original bit length of the message; the message itself is known to
# the attacker, but the secret key isn't, so you'll need to guess at
# it.
#
# This sounds more complicated than it is in practice.
#
# To implement the attack, first write the function that computes the
# MD padding of an arbitrary message and verify that you're generating
# the same padding that your SHA-1 implementation is using. This
# should take you 5-10 minutes.
#
# Now, take the SHA-1 secret-prefix MAC of the message you want to
# forge --- this is just a SHA-1 hash --- and break it into 32 bit
# SHA-1 registers (SHA-1 calls them "a", "b", "c", &c).
#
# Modify your SHA-1 implementation so that callers can pass in new
# values for "a", "b", "c" &c (they normally start at magic
# numbers). With the registers "fixated", hash the additional data you
# want to forge.
#
# Using this attack, generate a secret-prefix MAC under a secret key
# (choose a random word from /usr/share/dict/words or something) of
# the string:
#
#     "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
#
# Forge a variant of this message that ends with ";admin=true".

## This is a very useful attack.

# For instance: Thai Duong and Juliano Rizzo, who got to this attack
# before we did, used it to break the Flickr API.

require_relative 'sha1'
require_relative 'util'

PLAINTEXT = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'.bytes
SUFFIX = ';admin=true'.bytes
KEY = random_word.bytes
MAC = sha1_mac(PLAINTEXT, KEY)

def verify(buffer, mac)
  questionable_mac = sha1_mac(buffer, KEY)
  info("user mac: #{questionable_mac}")
  info("our mac : #{mac}")
  assert(mac == questionable_mac)
end

def sha1_padding(message_len)
  mask = 0xffffffff
  bit_len = message_len << 3
  padding = [0x80]
  padding << 0 while ((message_len + padding.size) % 64) != 56
  padding + [bit_len >> 32, bit_len & mask].pack('N2').bytes
end

def length_extension(mac, suffix, length)
  abcde = [mac].pack('H*').unpack('N5')
  SHA1.hexdigest(suffix, abcde, length)
end

(1..32).each do |key_length|
  info("testing key length: #{key_length}")
  padding = sha1_padding(PLAINTEXT.size + key_length)
  forged_message = PLAINTEXT + padding + SUFFIX
  forged_mac = length_extension(MAC, SUFFIX, key_length + forged_message.size)
  begin
    verify(forged_message, forged_mac)
    break
  rescue StandardError
  end
end
