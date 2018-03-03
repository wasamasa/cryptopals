## Break fixed-nonce CTR mode using substitutions

# Take your CTR encrypt/decrypt function and fix its nonce value to
# 0. Generate a random AES key.

# In *successive encryptions* (*not* in one big running CTR stream),
# encrypt each line of the base64 decodes of the following, producing
# multiple independent ciphertexts:
#
#     SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==
#     Q29taW5nIHdpdGggdml2aWQgZmFjZXM=
#     RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==
#     RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=
#     SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk
#     T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
#     T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=
#     UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==
#     QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=
#     T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl
#     VG8gcGxlYXNlIGEgY29tcGFuaW9u
#     QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==
#     QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=
#     QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==
#     QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=
#     QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
#     VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==
#     SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==
#     SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==
#     VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==
#     V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==
#     V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==
#     U2hlIHJvZGUgdG8gaGFycmllcnM/
#     VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=
#     QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=
#     VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=
#     V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=
#     SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==
#     U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==
#     U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=
#     VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==
#     QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu
#     SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=
#     VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs
#     WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=
#     SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0
#     SW4gdGhlIGNhc3VhbCBjb21lZHk7
#     SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=
#     VHJhbnNmb3JtZWQgdXR0ZXJseTo=
#     QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=
#
# (This should produce 40 short CTR-encrypted ciphertexts).
#
# Because the CTR nonce wasn't randomized for each encryption, each
# ciphertext has been encrypted against the same keystream. This is
# very bad.
#
# Understanding that, like most stream ciphers (including RC4, and
# obviously any block cipher run in CTR mode), the actual "encryption"
# of a byte of data boils down to a single XOR operation, it should be
# plain that:
#
#     CIPHERTEXT-BYTE XOR PLAINTEXT-BYTE = KEYSTREAM-BYTE
#
# And since the keystream is the same for every ciphertext:
#
#     CIPHERTEXT-BYTE XOR KEYSTREAM-BYTE = PLAINTEXT-BYTE (ie, "you don't
#     say!")
#
# Attack this cryptosystem piecemeal: guess letters, use expected
# English language frequence to validate guesses, catch common English
# trigrams, and so on.

## Don't overthink it.

# Points for automating this, but part of the reason I'm having you do
# this is that I think this approach is suboptimal.

require_relative 'util'

NONCE = 0
KEY = str(random_bytes(16))

INPUTS = [
  'SSBoYXZlIG1ldCB0aGVtIGF0IGNsb3NlIG9mIGRheQ==',
  'Q29taW5nIHdpdGggdml2aWQgZmFjZXM=',
  'RnJvbSBjb3VudGVyIG9yIGRlc2sgYW1vbmcgZ3JleQ==',
  'RWlnaHRlZW50aC1jZW50dXJ5IGhvdXNlcy4=',
  'SSBoYXZlIHBhc3NlZCB3aXRoIGEgbm9kIG9mIHRoZSBoZWFk',
  'T3IgcG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'T3IgaGF2ZSBsaW5nZXJlZCBhd2hpbGUgYW5kIHNhaWQ=',
  'UG9saXRlIG1lYW5pbmdsZXNzIHdvcmRzLA==',
  'QW5kIHRob3VnaHQgYmVmb3JlIEkgaGFkIGRvbmU=',
  'T2YgYSBtb2NraW5nIHRhbGUgb3IgYSBnaWJl',
  'VG8gcGxlYXNlIGEgY29tcGFuaW9u',
  'QXJvdW5kIHRoZSBmaXJlIGF0IHRoZSBjbHViLA==',
  'QmVpbmcgY2VydGFpbiB0aGF0IHRoZXkgYW5kIEk=',
  'QnV0IGxpdmVkIHdoZXJlIG1vdGxleSBpcyB3b3JuOg==',
  'QWxsIGNoYW5nZWQsIGNoYW5nZWQgdXR0ZXJseTo=',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4=',
  'VGhhdCB3b21hbidzIGRheXMgd2VyZSBzcGVudA==',
  'SW4gaWdub3JhbnQgZ29vZCB3aWxsLA==',
  'SGVyIG5pZ2h0cyBpbiBhcmd1bWVudA==',
  'VW50aWwgaGVyIHZvaWNlIGdyZXcgc2hyaWxsLg==',
  'V2hhdCB2b2ljZSBtb3JlIHN3ZWV0IHRoYW4gaGVycw==',
  'V2hlbiB5b3VuZyBhbmQgYmVhdXRpZnVsLA==',
  'U2hlIHJvZGUgdG8gaGFycmllcnM/',
  'VGhpcyBtYW4gaGFkIGtlcHQgYSBzY2hvb2w=',
  'QW5kIHJvZGUgb3VyIHdpbmdlZCBob3JzZS4=',
  'VGhpcyBvdGhlciBoaXMgaGVscGVyIGFuZCBmcmllbmQ=',
  'V2FzIGNvbWluZyBpbnRvIGhpcyBmb3JjZTs=',
  'SGUgbWlnaHQgaGF2ZSB3b24gZmFtZSBpbiB0aGUgZW5kLA==',
  'U28gc2Vuc2l0aXZlIGhpcyBuYXR1cmUgc2VlbWVkLA==',
  'U28gZGFyaW5nIGFuZCBzd2VldCBoaXMgdGhvdWdodC4=',
  'VGhpcyBvdGhlciBtYW4gSSBoYWQgZHJlYW1lZA==',
  'QSBkcnVua2VuLCB2YWluLWdsb3Jpb3VzIGxvdXQu',
  'SGUgaGFkIGRvbmUgbW9zdCBiaXR0ZXIgd3Jvbmc=',
  'VG8gc29tZSB3aG8gYXJlIG5lYXIgbXkgaGVhcnQs',
  'WWV0IEkgbnVtYmVyIGhpbSBpbiB0aGUgc29uZzs=',
  'SGUsIHRvbywgaGFzIHJlc2lnbmVkIGhpcyBwYXJ0',
  'SW4gdGhlIGNhc3VhbCBjb21lZHk7',
  'SGUsIHRvbywgaGFzIGJlZW4gY2hhbmdlZCBpbiBoaXMgdHVybiw=',
  'VHJhbnNmb3JtZWQgdXR0ZXJseTo=',
  'QSB0ZXJyaWJsZSBiZWF1dHkgaXMgYm9ybi4='
].map { |input| aes_ctr_encrypt(b64decode(input), NONCE, KEY) }

MAX_INPUT = INPUTS.max_by(&:length)
MIN_INPUT = INPUTS.min_by(&:length)

info("Max input length: #{MAX_INPUT.length}")
info("Min input length: #{MIN_INPUT.length}")

def score(input)
  count = 0
  WORDS.each do |word|
    next if word[/\d/]
    count += 1 if input.index(word)
  end
  count
end

def try_word_at(word, column)
  best_score = 0
  best_match = nil
  INPUTS.each do |line|
    next if column + word.length > line.length
    plaintext = word.bytes
    ciphertext = line.slice(column, word.length)
    key = xor_buffers(plaintext, ciphertext)
    output = ''
    INPUTS.each do |input|
      next if column + word.length > input.length
      output += str(xor_buffers(key, input.slice(column, word.length)))
      output += "\n"
    end
    score = score(output)
    next unless score > best_score
    best_match = [key, score, output]
    best_score = score
  end
  best_match
end

def try_word(word)
  best_score = 0
  best_match = nil
  max_column = MAX_INPUT.length - word.length
  max_column.times do |i|
    key, score, output = try_word_at(word, i)
    next unless score > best_score
    best_match = [key, score, i, output]
    best_score = score
  end
  best_match
end

def try_keystream_at(keystream, column)
  output = ''
  INPUTS.each do |input|
    ciphertext = input.slice(column, keystream.length)
    output += str(xor_buffers(keystream.take(ciphertext.length), ciphertext))
    output += "\n"
  end
  output
end

key, _score, column, _output = try_word('the')
info("First match at column: #{column}") # match found at column 11
puts try_keystream_at(key, 11)
puts

# 'bea' -> 'beauty'
key, = try_word_at('beauty', 11)
puts try_keystream_at(key, 11)
puts

# ' utter' -> 'utterly'
key, = try_word_at('utterly', 12)
puts try_keystream_at(key, 12)
puts

# 'ore swe' -> 'more sweet'
key, = try_word_at('more sweet', 11)
puts try_keystream_at(key, 11)
puts

# 'and beauti' -> 'and beautiful'
key, = try_word_at('and beautiful', 11)
puts try_keystream_at(key, 11)
puts

# 'eaningless wo' -> 'meaningless words'
key, = try_word_at('meaningless words', 10)
puts try_keystream_at(key, 10)
puts

# 'and sweet his tho' -> 'and sweet his thought'
key, = try_word_at('and sweet his thought', 10)
puts try_keystream_at(key, 10)
puts

# 'ave won fame in the e' -> 'have won fame in the end'
key, = try_word_at('have won fame in the end', 9)
puts try_keystream_at(key, 9)
puts

# 'ssed with a nod of the h' -> 'passed with a nod of the head'
key, = try_word_at('passed with a nod of the head', 7)
puts try_keystream_at(key, 7)
puts

# ', has been changed in his tur' -> ', has been changed in his turn'
key, = try_word_at(', has been changed in his turn', 7)
puts try_keystream_at(key, 7)
puts

# change to prepending bytes to keystream from other guessed texts

# 'ice more sweet than hers' -> 'voice more sweet than hers'
k, = try_word_at('voice more sweet than hers', 5)
key = k.slice(0, 2) + key
puts try_keystream_at(key, 5)
puts

# 'rible beauty is born.' -> 'terrible beauty is born.'
k, = try_word_at('terrible beauty is born.', 2)
key = k.slice(0, 3) + key
puts try_keystream_at(key, 2)
puts

# 'ansformed utterly:' -> 'Transformed utterly:'
k, = try_word_at('Transformed utterly:', 0)
key = k.slice(0, 2) + key
puts try_keystream_at(key, 0)
