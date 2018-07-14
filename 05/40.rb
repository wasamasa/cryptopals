require_relative '../util'

MESSAGE = b64decode('WW91IGJsYXN0LCBJIGJsYXN0LCBhbmQgdGhlbiB3aGF0Pw==')

def catch_messages
  messages = []
  public_keys = []
  3.times do
    public_key, = make_rsa_keys(generate_prime(256), generate_prime(256))
    messages << rsa_encrypt(MESSAGE, public_key)
    public_keys << public_key[1]
  end
  [public_keys, messages]
end

public_keys, messages = catch_messages

n_0 = public_keys[0]
n_1 = public_keys[1]
n_2 = public_keys[2]
n_012 = n_0 * n_1 * n_2

c_0 = messages[0] % n_0
c_1 = messages[1] % n_1
c_2 = messages[2] % n_2

m_s_0 = n_1 * n_2
m_s_1 = n_0 * n_2
m_s_2 = n_0 * n_1

# this is another subtle error in the description, you're meant to
# take the modulus of the whole sum, not the last term...
result = ((c_0 * m_s_0 * invmod(m_s_0, n_0)) +
          (c_1 * m_s_1 * invmod(m_s_1, n_1)) +
          (c_2 * m_s_2 * invmod(m_s_2, n_2))) % n_012

message = number_to_buffer(icbrt(result))
assert(MESSAGE == message)
info(str(message))
