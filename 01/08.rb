require_relative '../util'

inputs = File.open('08.txt', &:readlines).map { |line| hexdecode(line) }
inputs.each_with_index do |input, index|
  blocks = input.each_slice(16).to_a
  duplicate = find_duplicate(blocks)
  if duplicate
    info("Line #{index + 1} contains duplicate: #{hexencode(duplicate)}")
    puts hexencode(input)
  end
end
