## Clone an MT19937 RNG from its output

# The internal state of MT19937 consists of 624 32 bit integers.
#
# For each batch of 624 outputs, MT permutes that internal state. By
# permuting state regularly, MT19937 achieves a period of 2**19937,
# which is Big.
#
# Each time MT19937 is tapped, an element of its internal state is
# subjected to a tempering function that diffuses bits through the
# result.
#
# The tempering function is invertible; you can write an "untemper"
# function that takes an MT19937 output and transforms it back into
# the corresponding element of the MT19937 state array.
#
# To invert the temper transform, apply the inverse of each of the
# operations in the temper transform in reverse order. There are two
# kinds of operations in the temper transform each applied twice; one
# is an XOR against a right-shifted value, and the other is an XOR
# against a left-shifted value AND'd with a magic number. So you'll
# need code to invert the "right" and the "left" operation.
#
# Once you have "untemper" working, create a new MT19937 generator,
# tap it for 624 outputs, untemper each of them to recreate the state
# of the generator, and splice that state into a new instance of the
# MT19937 generator.
#
# The new "spliced" generator should predict the values of the
# original.

## Stop and think for a second.

# How would you modify MT19937 to make this attack hard? What would
# happen if you subjected each tempered output to a cryptographic
# hash?

require_relative 'util'
require_relative 'mt19937'

W = 32
U, D = [11, 0xFFFFFFFF]
S, B = [7, 0x9D2C5680]
T, C = [15, 0xEFC60000]
L = 18

def temper(y)
  y = y ^ ((y >> U) & D)
  y = y ^ ((y << S) & B)
  y = y ^ ((y << T) & C)
  y = y ^ (y >> L)
  lowest(y, W)
end

def untemper(y)
  y = y ^ (y >> L)
  y = y ^ ((lowest(y >> 0 * T, T) << 1 * T) & C)
  y = y ^ ((lowest(y >> 1 * T, T) << 2 * T) & C)
  y = y ^ ((lowest(y >> 0 * S, S) << 1 * S) & B)
  y = y ^ ((lowest(y >> 1 * S, S) << 2 * S) & B)
  y = y ^ ((lowest(y >> 2 * S, S) << 3 * S) & B)
  y = y ^ ((lowest(y >> 3 * S, S) << 4 * S) & B)
  y = y ^ (y >> U)
  y = y ^ (y >> (2 * U))
  lowest(y, W)
end

def clone(rng)
  state = rng.take(624)
  clone = MT19937.new(0)
  clone.state = state.map { |n| untemper(n) }
  clone
end

rng = MT19937.new(42)
rng2 = clone(rng)
assert(rng.take(1000) == rng2.take(1000))

# the basic problem here is that it's practical to untemper the
# diffused state, so a transformation that's hard to reverse would
# help here

# cryptographic hash functions are sufficient for this purpose, even
# something as broken as MD5
