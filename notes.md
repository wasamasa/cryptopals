# 01 Convert hex to base64

This is as easy as it gets.  If you fail here, go improve your
programming skills first.  If it's too easy for you, implement base64
instead of using the standard library implementation.  I've used this
chance to create a `util.rb` which holds all reused code.  The first
function I wrote is `assert` to document all implicit assumptions, I
recommend doing the same, especially in a language with a dynamic type
system.  It doubles as a light-weight testing tool.

# 02 Fixed XOR

XOR is the bread-and-butter operator in cryptography.  Expect to use
it a lot.

# 03 Single-byte XOR cipher

It took me some head-scratching to come up with a good scoring metric.
An obvious one is to give strings with unprintable characters a
failing score, however that's not enough to tell whether they resemble
English.  I've looked at some statistics stuff, found an English
histogram and implemented the [Chi-squared test](https://en.wikipedia.org/wiki/Chi-squared_test) to compare the
encountered distribution with the ideal one.  It's not hard, but
definitely no 9th grader mathematics.

# 04 Detect single-character XOR

Easy-peasy.  If a string has been encrypted by single-character XOR,
it will have a good English score for a particular byte, otherwise
not.

# 05 Implement repeating-key XOR

The only way you can screw this up is by not taking into account that
the length of the plaintext you're encrypting doesn't have to be a
multiple of the key length.  This gotcha will come up in a few more
exercises.

# 06 Break repeating-key XOR

To implement the Hamming distance it's useful to have a `popcount`
function.  If you xor two bytes, the equal bits will become ones and
the unequal ones become zeroes.  Count the ones with `popcount` and
you get the Hamming distance.

There's a few error-prone parts in this challenge that require
tweaking.  For step #4 I went with four key-sized blocks.  I also
ended up improving my English scoring function to figure out the
correct text.  Instead of just comparing the given with the ideal
histogram, I added a check for unusual characters: If there's less
than there typically are, double the score.  The reasoning here is
that an unusually high number of particular letters is still more
likely to look like English than an unusually high number of
non-letters.

# 07 AES in ECB mode

Oh noes, OpenSSL.  The APIs are weird, so the greatest issue here is
figuring out how to use it.

# 08 Detect AES in ECB mode

Could this be as easy as finding duplicates as long as the block size?
Yes!

# 09 Implement PKCS#7 padding

PKCS#7 padding is simple, but has one caveat that's easy to overlook.
Assuming the length of the plaintext to be padded is already a
multiple of the block size, you still have to add padding as large as
the block size.  Otherwise unpadding will fail.

# 10 Implement CBC mode

The big realization here is that ECB used on a single block can be
used to encrypt and combine multiple blocks independently.  This
allows you to implement CBC (and later, CTR) in terms of it.  Just
make sure that if you decrypt, OpenSSL doesn't try to remove any
PKCS#7 padding for you because that will fail horribly.

# 11 An ECB/CBC detection oracle

Oracles are great.  In cryptography, an oracle refers to a function
that can be used by the attacker to gain a piece of information.  This
one doesn't seem to be terribly useful as it only returns encrypted
text, however it still manages to leak information about the used
cipher mode.  Just remember about challenge #08 and you'll be golden.

# 12 Byte-at-a-time ECB decryption (Simple)

The most involved part of this is detecting the block size of the
cipher.  Other than that it's a straight-forward implementation of the
description.

# 13 ECB cut-and-paste

I lazied out initially and reused Ruby's support for `form-urlencoded`
data.  This was a bad idea as it made the challenge impossible to
solve, not only will it touch the ampersand and equals characters, but
everything unprintable as well...

If you're wondering why, consider that even data encrypted with ECB
needs to be padded (how else would you encrypt arbitrarily long data
that may or may not match up with the cipher's block size?).  If you
cut and paste at the block boundaries, the block going at the end
needs to resemble correct padding.  This is going to be a problem if
the sanitizing function mangles binary data.

# 14 Byte-at-a-time ECB decryption (Harder)

It took me a while to figure this one out.  You can mostly solve this
challenge like #12, but need to detect the length of the random prefix
first.  Once that's been taken care of you can proceed with creating
the dictionary of bytes, with the caveat that you may need to generate
more padding to fill up the random prefix until the next block
boundary.  The rest works the same.

# 15 PKCS#7 padding validation

Remember that there must be at least one byte of padding and that the
last byte tells how large the padding is.

# 16 CBC bitflipping attacks

I'm afraid there's no bitflipping operator, but XOR comes close
enough.  Given an existing byte and a target byte, XORing them gives
you a number.  XORing the existing byte by that number will yield the
target byte.  Use this to craft an input string to bitflip into the
target string.

# 17 The CBC padding oracle

I found [the paper for this attack](https://infoscience.epfl.ch/record/52417/files/IC_TECH_REPORT_200150.pdf) hard to comprehend, fortunately
there are many explanations on the details available online.  There's
much that can go wrong with your implementation.  You'll have to work
one block each, but in reverse, need to keep the correct padding in
mind, piece together information from already guessed bytes and apply
the IV to the result (something most explanations of the attack I've
found gloss over).  Still, the attack is conceptually elegant and
breaks cryptosystems that don't use signing, so it's definitely worth
doing.

# 18 Implement CTR, the stream cipher mode

CTR isn't nearly as confusing to get right as CBC.  The only thing to
watch out for is how to encode a 8-byte number in little-endian.
You'll want to use `pack` if your language provides it.

# 19 Break fixed-nonce CTR mode using substitutions

Throws one back to the first challenges, huh.  You'll want to look up
English trigrams and test for them first, then score by a metric like
number of intelligible words found in the decrypted text.  Once you've
found a promising part of the keystream, you can guess more words in
the partially decrypted text.  Bonus points if you manage creating a
visualization of the process.

# 20 Break fixed-nonce CTR statistically

This is challenge #06 all over again.  It saddens me a bit that you
have to truncate the messages, but the full decrypted text can be
easily found online.

# 21 Implement the MT19937 Mersenne Twister RNG

I've made the mistake of looking at [the underlying theory](https://en.wikipedia.org/wiki/Semisimple_Lie_algebra) to
implement it from the original paper.  Don't.  The field
visualizations are pretty, but won't help you at all.  Pseudocode from
Wikipedia is much better, you'll want to go for the 32-bit variant.
If you're having issues, grab their Python implementation, add logging
and compare the output of intermediate state with yours.  This trick
works with other things as well, such as debugging hash functions.

# 22 Crack an MT19937 seed

The RNG implemented in #21 will always return the same sequence of
random numbers given the same seed.  Considering that the seed is some
past point in time, you can establish a range of possible seeds and
try each until you find one leading to the RNG output you've captured
before.

# 23 Clone an MT19937 RNG from its output

This one is rather annoying to get right.  Observing enough numbers to
get a tempered internal state is the easy part, the hard part is
untempering them.  I eventually gave up figuring out the equivalent
transforms and looked them up online.

# 24 Create the MT19937 stream cipher and break it

The first challenge can be brute-forced.  The prefix size can be
deducted from looking at the ciphertext size.  For each possible seed
value fast-forward the RNG by the amount of prefix bytes, then check
for the remaining bytes whether XORing them with the keystream gives
you the known plaintext.

The second challenge is even easier.  A password reset token's
randomness depends on the exact time it was created.  Create one at
the same time and they'll be equal.  If they aren't, well, the
captured reset token must have been created at a different time...

# 25 Break "random access read/write" AES CTR

This one sounds harder than it is.  The key is to realize that if the
attacker replaces a piece of the ciphertext and the result is the same as
before, they must have chosen a piece equal to the plaintext.  To
guess as little as possible, edit one byte at a time.  I initially
implemented the `edit` function as stupidly as possible, but that made
guessing the plaintext very slow, so the hardest part of the challenge
was implementing a more efficient `edit` function that synthesized the
necessary part of the keystream, XORed it with the new plaintext and
returned the ciphertext with the result patched in.

edit: I found a way more efficient way. The `edit` API call gives you
a way to generate an attacker-controlled ciphertext using the same
nonce and key.  Encryption combines the plaintext with a keystream
that is the same for both ciphertexts.  Therefore, XORing both
ciphertexts will cancel the keystreams out and give you the
combination of the unknown plaintext and the known one.  XOR the
result with the known plaintext and you've recovered the unknown one.
The lesson from this one is probably that you should use a new nonce
when re-encrypting.

# 26 CTR bitflipping

Same approach as with challenge #16 except that bitflipping will
affect the same position (as opposed to the next block).

# 27 Recover the key from CBC with IV=Key

Implement exactly what's described here.  It will miraculously reveal
the key.  Note that the attacker *must* receive an error message
containing the mogrified plaintext because that's the one you'll slice
apart in the final step.

# 28 Implement a SHA-1 keyed MAC

I looked up a pure Ruby implementation of SHA1 on Rosetta Code.  Make
sure it can process bytes, just like all of your utility functions.
For the test I wrote a verification function receiving a buffer and
MAC which checks whether the MAC is the same as running `sha1_mac` on
the buffer and secret.  To demonstrate that it can detect tampering I
wrote two assertions where either the buffer or mac had a byte
mutated.

# 29 Break a SHA-1 keyed MAC using length extension

First of all, get acquainted with your SHA1 implementation,
particularly with how it generates padding (which includes the length
of the message).  You'll have to modify it to allow starting from a
different internal state and more importantly, to use a custom length
in the final padding bit.  If you forget doing that, you'll end up
with a different padding than the server validating the MAC would.
Alternatively, consider splitting it up into `initialize`, `digest`
and `finalize`.

The actual attack requires guessing the length of the secret prefix,
so just repeat it with different lengths until you guess the right
one.

# 30 Break an MD4 keyed MAC using length extension

Same deal as with #29.  MD4 uses a construction similar to SHA1, so no
surprises here.

# 31 Implement and break HMAC-SHA1 with an artificial timing leak

This one is fun.  Implementing HMAC as described on Wikipedia is easy,
the hardest part here is writing that web service verifying HMACs.
For the actual attack, consider that `insecure_compare` will either
exit immediately (because the compared bytes don't match) or succeeds,
sleeps and continues comparing the next bytes.  You can therefore tell
what the right byte is by trying all for a given position and picking
the one that took longest.  Repeat for the next position, but with the
correctly guessed byte fixed.  You'll eventually have tested the
complete HMAC and the web service will return status code 200 for it.

I recommend displaying the found bytes Hollywood-style, like [here](http://brause.cc/gifs/hollywoodhacking.gif).

# 32 Break HMAC-SHA1 with a slightly less artificial timing leak

This is a bit harder than #31 because it's not guaranteed that
measuring once is enough to tell the correct byte.  You'll have to
come up with some way to smooth the measurement errors, like by
measuring multiple times for each candidate and averaging the times.
I went for guessing characters repeatedly (at least twice) until more
than 50% of my guesses resulted in the same character.

# 33 Implement Diffie-Hellman

Get acquainted with modular arithmetic and implement `modexp`.
Alternatively, use the OpenSSL version.  Implementing DH with it is
trivial.

# 34 Implement a MITM key-fixing attack on Diffie-Hellman with parameter injection

Ah, protocols.  I've used named pipes to allow communication between
processes, with one per recipient.  For example if A wants to send
text to B, A writes into B's named pipe; at some point B will read
from its named pipe and thus receive the message.  You could
alternatively use some variation on OOP and keep things in one
process, but I don't find it as neat.

The presented MITM attack has the effect of turning the shared key
into zero, no matter the user inputs.  This means that Mallory can
decrypt all messages encrypted with that key.

# 35 Implement DH with negotiated groups, and break with malicious "g" parameters

This MITM attack is slightly less realistic because A and B won't
agree on the same shared secret and the communication will fail after
the first message has been exchanged.  Mallory can still figure out
that message as the key is predictable again.  Either do some basic
algebra to figure out the exact value or observe what values occur.

# 36 Implement Secure Remote Password (SRP)

The description for this one is misleading.  SRP is all about the
client never sending a password to the server.  Another difference is
that the protocol is split into a registration and authentication
phase.  Other than that the description is valid.

# 37 Break SRP with a zero key

Do exactly as told.  Have a client register on your server, then
simulate a rogue client with the suggested parameters.  You'll find
that they result in the shared secret becoming zero.

# 38 Offline dictionary attack on simplified SRP

Flawed description again (why would the server need to crack the
password if it already knew it?).  Use the parameters on the server
side to crack the client credentials by bruteforcing with a dictionary
and checking for every possible password what `v` would be.  Once it
matches, you have a compatible password.

# 39 Implement RSA

OpenSSL provides both prime generation and `invmod`.  They'll be
faster than your own implementations, but feel free to implement them
anyway for the educational effect.  Everything else is easy.

# 40 Implement an E=3 RSA Broadcast attack

CRT stands for Chinese Remainder Theorem, you may want to watch a
YouTube video on how to apply it for solving an equation similar to
what's given in this exercise.  Implement an integer cube root if you
don't have one in your language, it can be something as simple as
doing a binary search.  Note that the description of the algorithm is
subtly flawed, you'll have to take the modulus of the whole sum, not
the last term...

# 41 Implement unpadded message recovery oracle

I found OOP useful to model the server setting, but there isn't really
a need to do it that way. Remember that `(modexp(S, E, N) * C) % N` is
equivalent to `(S * C) % N` and `(P_ * invmod(S, N)) % N` is to `(P_ /
S) % N`.  Modular arithmetic is easy to get wrong by forgetting a
modulo at some point, so err on the side of caution.

# 42 Bleichenbacher's e=3 RSA Attack

A 1024-bit RSA signature refers to the modulus being 1024 bits long,
so you'll need to generate two 512 bit primes.  For the
signature, [use MD5 as that produces the smallest ASN.1 padding](https://tools.ietf.org/html/rfc3447#section-9.2)
and leaves you more room for fooling around.  The mentioned write-up
makes it very clear how exactly the forged signature should end up
looking, use that with your integer cube root function to calculate
the forged signature.

# 43 DSA key recovery from nonce

I found DSA far more annoying to get right than RSA, simply because
there's far more math and parameters
involved.  [The original DSA paper](https://web.archive.org/web/20131226115544/http://csrc.nist.gov/publications/fips/fips1861.pdf) includes test data in the end
which greatly helps with debugging your implementation.  Cracking the
key with the given formula is just a matter of brute force.  One more
thing that might trip you up, the SHA1 hash given for verification has
to be applied to the hexadecimal string representation of the private
key...

# 44 DSA nonce recovery from repeated nonce

It's easy to find the messages with a repeated `k`, they will have the
same `r`.  Pick two messages of that kind and apply the given
formula.  If you want an actual challenge, puzzle the formula together
on your own.  Hint: Start off with subtracting two signature equations
from each other.

# 45 DSA parameter tampering

Same story as in #34 and #35 except that you aren't told to simulate
networking.  The magic signature thing is something I haven't figured
out yet, but it should be a matter of algebra.

# 46 RSA parity oracle

Implement the algorithm exactly as described.  You'll want to use
decimals or rationals for the boundaries to guess the correct number,
otherwise the last byte will come out wrong.  The Hollywood-style
display is pretty nice, see it [here](http://brause.cc/gifs/hollywoodhacking2.gif).

# 47 Bleichenbacher's PKCS 1.5 Padding Oracle (Simple Case)

I went way too many times over [the Bleichenbacher paper](http://archiv.infsec.ethz.ch/education/fs08/secsem/Bleichenbacher98.pdf) (and a few
other explanations of the attack) until I was sure I understood every
step of the algorithm.  This would have been much easier to comprehend
with pseudocode.  Anyway, you'll want to have a `floor` / `ceil`
function, be it to use on floats or for integer division.  There is no
blinding needed whatsoever, so just use a `s0` of 1.  The algorithm
boils down to starting with step 2a, then entering a loop of step 3
and 2c.  The final number is a differently padded plaintext.

# 48 Bleichenbacher's PKCS 1.5 Padding Oracle (Complete Case)

Same as #47, but you'll need to flesh out your code to actually work
with multiple intervals.  The loop consists of step 3 followed by
either step 2b or 2c, depending on whether step 3 gave you multiple
intervals or not.
