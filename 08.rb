## Detect AES in ECB mode

# In this file are a bunch of hex-encoded ciphertexts.
#
# One of them has been encrypted with ECB.
#
# Detect it.
#
# Remember that the problem with ECB is that it is stateless and
# deterministic; the same 16 byte plaintext block will always produce
# the same 16 byte ciphertext.

require_relative 'util'

inputs = File.open('08.txt', &:readlines).map { |line| hexdecode(line) }
inputs.each_with_index do |input, index|
  blocks = input.each_slice(16).to_a
  duplicate = find_duplicate(blocks)
  if duplicate
    info("Line #{index + 1} contains duplicate: #{hexencode(duplicate)}")
    puts hexencode(input)
  end
end
