require_relative '../util'
# we'll want precise math as explained on
# https://secgroup.dais.unive.it/wp-content/uploads/2012/11/Practical-Padding-Oracle-Attacks-on-RSA.html

P = generate_prime(512)
Q = generate_prime(512)
E = 2**16 + 1
PUBLIC, PRIVATE = make_rsa_keys(P, Q, E)
MESSAGE = b64decode('VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==')
CIPHERTEXT = rsa_encrypt(MESSAGE, PUBLIC)
EPSILON = 1e-6
DELAY = 0.005

assert(rsa_decrypt(CIPHERTEXT, PRIVATE) == MESSAGE)

def parity_oracle(c)
  message = rsa_decrypt(c, PRIVATE)
  buffer_to_number(message).even?
end

def sanitize(string)
  string.gsub(/[^[:print:]]/, '?')
end

$last_length = nil

def report_progress(string)
  print " #{' ' * $last_length}\r" if $last_length
  print " #{string}\r"
  $last_length = string.length
end

_, N = PUBLIC
upper = N
lower = 0
c = CIPHERTEXT

loop do
  report_progress(sanitize(str(number_to_buffer(upper.to_i))))
  c = (modexp(2, E, N) * c) % N
  if parity_oracle(c)
    upper = Rational(upper + lower, 2)
  else
    lower = Rational(upper + lower, 2)
  end
  break if (upper - lower) < EPSILON
  sleep(DELAY)
end
puts
