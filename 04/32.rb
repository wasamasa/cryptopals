require 'benchmark'
require 'net/http'
require_relative '../util'

def http_request(file, hmac)
  uri = URI("http://localhost:9000/test?file=#{file}&signature=#{hmac}")
  res = Net::HTTP.get_response(uri)
  res.code.to_i
end

def show_progress(hmac)
  print " trying #{hmac}\r"
end

def guess_char(file, hmac, index)
  timings = {}
  '0123456789abcdef'.bytes.map(&:chr).shuffle.each do |char|
    new_hmac = hmac.clone
    new_hmac[index] = char
    show_progress(new_hmac)
    time = Benchmark.realtime { http_request(file, new_hmac) }
    timings[char] = time
  end
  timings.max_by { |_, v| v }[0]
end

MIN_ATTEMPTS = 2
MAX_ATTEMPTS = 25

def guess_char_repeatedly(file, hmac, index)
  guesses = ''
  MIN_ATTEMPTS.times { guesses << guess_char(file, hmac, index) }
  attempts = MIN_ATTEMPTS
  loop do
    raise "couldn't guess char" if attempts > MAX_ATTEMPTS
    best_guess = frequencies(guesses).max_by { |_, v| v }
    return best_guess[0] if best_guess[1] > 0.5
    guesses << guess_char(file, hmac, index)
    attempts += 1
  end
end

def guess_hmac(file)
  hmac = '0000000000000000000000000000000000000000'
  show_progress(hmac)
  hmac.length.times do |i|
    hmac[i] = guess_char_repeatedly(file, hmac, i)
    show_progress(hmac)
  end
  hmac
end

file = random_word
hmac = guess_hmac(file)
puts
assert(http_request(file, hmac) == 200)
info("HMAC for #{file}: #{hmac}")
