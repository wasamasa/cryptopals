require_relative '../util'
require_relative '../mt19937'

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
