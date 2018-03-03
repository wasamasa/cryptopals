## Break "random access read/write" AES CTR

# Back to CTR. Encrypt the recovered plaintext from this file (the ECB
# exercise) under CTR with a random key (for this exercise the key
# should be unknown to you, but hold on to it).
#
# Now, write the code that allows you to "seek" into the ciphertext,
# decrypt, and re-encrypt with different plaintext. Expose this as a
# function, like, "edit(ciphertext, key, offset, newtext)".
#
# Imagine the "edit" function was exposed to attackers by means of an
# API call that didn't reveal the key or the original plaintext; the
# attacker has the ciphertext and controls the offset and "new text".
#
# Recover the original plaintext.

## Food for thought.

# A folkloric supposed benefit of CTR mode is the ability to easily
# "seek forward" into the ciphertext; to access byte N of the
# ciphertext, all you need to be able to do is generate byte N of the
# keystream. Imagine if you'd relied on that advice to, say, encrypt a
# disk.

require_relative 'util'

# same procedure as in challenge #7
PLAINTEXT = aes_ecb_decrypt(b64decode(File.open('25.txt', &:read)),
                            'YELLOW SUBMARINE')
NONCE = 42
KEY = str(random_bytes(16))
CIPHERTEXT = aes_ctr_encrypt(PLAINTEXT, NONCE, KEY)

def edit(ciphertext, nonce, key, offset, newtext)
  assert(offset < ciphertext.size)
  assert(offset + newtext.size <= ciphertext.size)
  block_skip = offset / 16
  block_count = (newtext.size / 16) + 1
  hunk = aes_ctr_decrypt(ciphertext, nonce, key,
                         block_skip, block_count, block_skip)
  newtext.size.times { |i| hunk[offset % 16 + i] = newtext[i] }
  patch = aes_ctr_encrypt(hunk, nonce, key, 0, block_count, block_skip)
  patched = ciphertext.clone
  patch.size.times { |i| patched[block_skip * 16 + i] = patch[i] }
  patched
end

def api_edit(ciphertext, offset, newtext)
  edit(ciphertext, NONCE, KEY, offset, newtext)
end

plaintext = 'mississippi bank01234567890'.bytes
ciphertext = aes_ctr_encrypt(plaintext, NONCE, KEY)
offset = 16
newtext = '*'.bytes
new_ciphertext = edit(ciphertext, NONCE, KEY, offset, newtext)
editedtext = 'mississippi bank*1234567890'.bytes
assert(aes_ctr_decrypt(new_ciphertext, NONCE, KEY) == editedtext)

# the idea here is that if you edit a byte of the ciphertext and the
# result is the same, you've guessed that byte of the plaintext

def guess_byte(ciphertext, offset)
  (0..127).each do |byte|
    return byte if ciphertext == api_edit(ciphertext, offset, [byte])
  end
  raise "couldn't guess byte"
end

CIPHERTEXT.size.times { |i| print guess_byte(CIPHERTEXT, i).chr }
