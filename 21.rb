## Implement the MT19937 Mersenne Twister RNG

# You can get the psuedocode for this from Wikipedia.
#
# If you're writing in Python, Ruby, or (gah) PHP, your language is
# probably already giving you MT19937 as "rand()"; don't use
# rand(). Write the RNG yourself.

require_relative 'util'
require_relative 'mt19937'

rng = MT19937.new(42)
a = rng.take(10)
b = rng.take(10)
assert(a != b)

rng = MT19937.new(42)
a = rng.take(10)
rng = MT19937.new(23)
b = rng.take(10)
assert(a != b)

rng = MT19937.new(42)
a = rng.take(10)
rng = MT19937.new(42)
b = rng.take(10)
assert(a == b)
