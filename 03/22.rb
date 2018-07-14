require_relative '../util'
require_relative '../mt19937'

def random_ints(seed, n)
  rng = MT19937.new(seed)
  rng.take(n)
end

def random_wait
  info('waiting a bit...')
  sleep(rand(40..1000))
end

def wait_for_it
  random_wait
  rng = MT19937.new(Time.now.to_i)
  random_wait
  rng.extract_number
end

def crack_it(rng_output)
  to = Time.now.to_i
  from = to - 2000
  (from..to).reverse_each do |seed|
    rng = MT19937.new(seed)
    return seed if rng.extract_number == rng_output
  end
  raise 'Seed not found'
end

# sanity check
seed = rand(0..1000)
a = random_ints(seed, 100)
b = random_ints(seed, 100)
assert(a == b)

rng_output = wait_for_it
info("RNG output: #{rng_output}")
seed = crack_it(rng_output)
info("RNG seed: #{seed}")
