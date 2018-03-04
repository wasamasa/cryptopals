## Break repeating-key XOR

## It is officially on, now.

# This challenge isn't conceptually hard, but it involves actual
# error-prone coding. The other challenges in this set are there to
# bring you up to speed. This one is there to qualify you. If you can
# do this one, you're probably just fine up to Set 6.

# There's a file here. It's been base64'd after being encrypted with
# repeating-key XOR.
#
# Decrypt it.
#
# Here's how:
#
# 1. Let KEYSIZE be the guessed length of the key; try values from 2
# to (say) 40.
#
# 2. Write a function to compute the edit distance/Hamming distance
# between two strings. The Hamming distance is just the number of
# differing bits. The distance between:
#
#     this is a test
#
# and
#
#     wokka wokka!!!
#
# is 37. Make sure your code agrees before you proceed.
#
# 3. For each KEYSIZE, take the first KEYSIZE worth of bytes, and the
# second KEYSIZE worth of bytes, and find the edit distance between
# them. Normalize this result by dividing by KEYSIZE.
#
# 4. The KEYSIZE with the smallest normalized edit distance is
# probably the key. You could proceed perhaps with the smallest 2-3
# KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average
# the distances.
#
# 5. Now that you probably know the KEYSIZE: break the ciphertext into
# blocks of KEYSIZE length.
#
# 6. Now transpose the blocks: make a block that is the first byte of
# every block, and a block that is the second byte of every block, and
# so on.
#
# 7. Solve each block as if it was single-character XOR. You already
# have code to do this.
#
# 8. For each block, the single-byte XOR key that produces the best
# looking histogram is the repeating-key XOR key byte for that
# block. Put them together and you have the key.
#
# This code is going to turn out to be surprisingly useful later
# on. Breaking repeating-key XOR ("Vigenere") statistically is
# obviously an academic exercise, a "Crypto 101" thing. But more
# people "know how" to break it than can actually break it, and a
# similar technique breaks something much more important.

## No, that's not a mistake.

# We get more tech support questions for this challenge than any of
# the other ones. We promise, there aren't any blatant errors in this
# text. In particular: the "wokka wokka!!!" edit distance really is
# 37.

require_relative 'util'

assert(hamming('this is a test', 'wokka wokka!!!') == 37)

input = b64decode(File.open('06.txt', &:read))
key_sizes = []
(2..40).each do |key_size|
  buf1 = input.slice(0, key_size)
  buf2 = input.slice(key_size, key_size)
  buf3 = input.slice(key_size * 2, key_size)
  buf4 = input.slice(key_size * 3, key_size)
  distance1 = hamming(buf1, buf2) / key_size.to_f
  distance2 = hamming(buf2, buf3) / key_size.to_f
  distance3 = hamming(buf3, buf4) / key_size.to_f
  distance = (distance1 + distance2 + distance3) / 3
  key_sizes << [distance, key_size]
end

best_key_sizes = key_sizes.sort_by { |d, _| d }.map { |_, k| k }.take(3)

keys = []
best_key_sizes.each do |key_size|
  key_bytes = []
  blocks = input.each_slice(key_size).to_a
  blocks[-1] = rightpad(blocks[-1], blocks[0].size, nil)
  blocks.transpose.each do |block|
    best_score = 0
    best_key_byte = nil
    (0..255).each do |key_byte|
      solution = str(xor_buffer_with_byte(block.compact, key_byte))
      score = english_score(solution)
      if score > best_score
        best_score = score
        best_key_byte = key_byte
      end
    end
    key_bytes << best_key_byte
  end
  keys << str(key_bytes)
end

info("Possible keys: #{keys}")

translations = keys.map { |key| str(xor_buffer_with_bytes(input, key.bytes)) }
puts translations.max_by { |t| english_score(t) }
