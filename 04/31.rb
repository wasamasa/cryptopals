require 'benchmark'
require 'net/http'
require_relative '../util'

assert(sha1_hmac([], []) == 'fbdb1d1b18aa6c08324b7d64b71fb76370690e1d')
assert(sha1_hmac('The quick brown fox jumps over the lazy dog'.bytes,
                 'key'.bytes) == 'de7c9b85b8b78aa6bc8a7a36f70a90701c9db4d9')

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

def guess_hmac(file)
  hmac = '0000000000000000000000000000000000000000'
  show_progress(hmac)
  hmac.length.times do |i|
    hmac[i] = guess_char(file, hmac, i)
    show_progress(hmac)
  end
  hmac
end

file = random_word
hmac = guess_hmac(file)
puts
assert(http_request(file, hmac) == 200)
info("HMAC for #{file}: #{hmac}")
