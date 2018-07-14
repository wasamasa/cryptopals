require_relative '../sha1'
require_relative '../util'

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
