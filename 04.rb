## Detect single-character XOR

# One of the 60-character strings in this file has been encrypted by
# single-character XOR.
#
# Find it.
#
# (Your code from #3 should help.)

require_relative 'util'

inputs = File.open('04.txt') { |f| f.readlines.map(&:chomp) }
best_score = 0
best_solution = ''

inputs.each do |input|
  input = hexdecode(input)
  (0..255).each do |key|
    solution = str(xor_buffer_with_byte(input, key))
    score = english_score(solution)
    if score > best_score
      best_score = score
      best_solution = solution
    end
  end
end

info("score: #{best_score}")
puts best_solution
