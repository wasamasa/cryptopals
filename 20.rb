## Break fixed-nonce CTR statistically

# In this file find a similar set of Base64'd plaintext. Do with them
# exactly what you did with the first, but solve the problem
# differently.
#
# Instead of making spot guesses at to known plaintext, treat the
# collection of ciphertexts the same way you would repeating-key XOR.
#
# Obviously, CTR encryption appears different from repeated-key XOR,
# *but with a fixed nonce they are effectively the same thing*.
#
# To exploit this: take your collection of ciphertexts and truncate
# them to a common length (the length of the smallest ciphertext will
# work).
#
# Solve the resulting concatenation of ciphertexts as if for
# repeating- key XOR, with a key size of the length of the ciphertext
# you XOR'd.

require_relative 'util'

NONCE = 0
KEY = random_bytes(16)

INPUTS = File.open('20.txt', &:readlines)
             .map { |line| aes_ctr_encrypt(b64decode(line), KEY, NONCE) }

MAX_INPUT = INPUTS.max_by(&:length)
MIN_INPUT = INPUTS.min_by(&:length)

info("Max input length: #{MAX_INPUT.length}")
info("Min input length: #{MIN_INPUT.length}")

KEY_SIZE = MIN_INPUT.length

INPUT = INPUTS.flat_map { |input| input.slice(0, KEY_SIZE) }

key_bytes = []
blocks = INPUT.each_slice(KEY_SIZE).to_a.transpose
blocks.each do |block|
  best_score = 0
  best_key_byte = nil
  256.times do |key_byte|
    solution = str(xor_buffer_with_byte(block.compact, key_byte))
    score = english_score(solution)
    next unless score > best_score
    best_score = score
    best_key_byte = key_byte
  end
  key_bytes << best_key_byte
end

output = str(xor_buffers(INPUT, key_bytes * INPUTS.length))
puts output.chars.each_slice(KEY_SIZE).map(&:join).join("\n")
