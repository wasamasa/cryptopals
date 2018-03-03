## Break an MD4 keyed MAC using length extension

# Second verse, same as the first, but use MD4 instead of
# SHA-1. Having done this attack once against SHA-1, the MD4 variant
# should take much less time; mostly just the time you'll spend
# Googling for an implementation of MD4.

## You're thinking, why did we bother with this?

# Blame Stripe. In their second CTF game, the second-to-last challenge
# involved breaking an H(k, m) MAC with SHA1. Which meant that SHA1
# code was floating all over the Internet. MD4 code, not so much.

require_relative 'md4'
require_relative 'util'

require 'openssl'
assert(MD4.hexdigest('test'.bytes) == OpenSSL::Digest::MD4.hexdigest('test'))

PLAINTEXT = 'comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon'.bytes
SUFFIX = ';admin=true'.bytes
KEY = random_word
MAC = md4_mac(PLAINTEXT, KEY)

def verify(buffer, mac)
  questionable_mac = md4_mac(buffer, KEY)
  info("user mac: #{questionable_mac}")
  info("our mac : #{mac}")
  assert(mac == questionable_mac)
end

def md4_padding(message_len)
  mask = (1 << 32) - 1
  bit_len = message_len << 3
  padding = [0x80]
  padding << 0 while ((message_len + padding.size) % 64) != 56
  padding + [bit_len & mask, bit_len >> 32].pack('V2').bytes
end

def length_extension(mac, suffix, length)
  abcd = [mac].pack('H*').unpack('V4')
  MD4.hexdigest(suffix, abcd, length)
end

(1..32).each do |key_length|
  info("testing key length: #{key_length}")
  padding = md4_padding(PLAINTEXT.size + key_length)
  forged_message = PLAINTEXT + padding + SUFFIX
  forged_mac = length_extension(MAC, SUFFIX, key_length + forged_message.size)
  begin
    verify(forged_message, forged_mac)
    break
  rescue StandardError
  end
end
