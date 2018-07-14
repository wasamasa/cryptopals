require_relative '../util'

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
