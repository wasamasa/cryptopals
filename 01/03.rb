require_relative '../util'

input = hexdecode('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
best_score = 0
best_solution = ''

(0..255).each do |key|
  solution = str(xor_buffer_with_byte(input, key))
  score = english_score(solution)
  if score > best_score
    best_score = score
    best_solution = solution
  end
end

info("score: #{best_score}")
puts best_solution
