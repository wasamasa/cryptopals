## Implement and break HMAC-SHA1 with an artificial timing leak

# The pseudocode on Wikipedia should be enough. HMAC is very easy.
#
# Using the web framework of your choosing (Sinatra, web.py,
# whatever), write a tiny application that has a URL that takes a
# "file" argument and a "signature" argument, like so:
#
#     http://localhost:9000/test?file=foo&signature=46b4ec586117154dacd49d664e5d63fdc88efb51
#
# Have the server generate an HMAC key, and then verify that the
# "signature" on incoming requests is valid for "file", using the "=="
# operator to compare the valid MAC for a file with the "signature"
# parameter (in other words, verify the HMAC the way any normal
# programmer would verify it).
#
# Write a function, call it "insecure_compare", that implements the ==
# operation by doing byte-at-a-time comparisons with early exit (ie,
# return false at the first non-matching byte).
#
# In the loop for "insecure_compare", add a 50ms sleep (sleep 50ms
# after each byte).
#
# Use your "insecure_compare" function to verify the HMACs on incoming
# requests, and test that the whole contraption works. Return a 500 if
# the MAC is invalid, and a 200 if it's OK.
#
# Using the timing leak in this application, write a program that
# discovers the valid MAC for any file.

## Why artificial delays?

# Early-exit string compares are probably the most common source of
# cryptographic timing leaks, but they aren't especially easy to
# exploit. In fact, many timing leaks (for instance, any in C, C++,
# Ruby, or Python) probably aren't exploitable over a wide-area
# network at all. To play with attacking real-world timing leaks, you
# have to start writing low-level timing code. We're keeping things
# cryptographic in these challenges.

require 'benchmark'
require 'net/http'
require_relative 'util'

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
