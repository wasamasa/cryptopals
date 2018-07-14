require_relative '../util'

a = hexdecode('1c0111001f010100061a024b53535009181c')
b = hexdecode('686974207468652062756c6c277320657965')
expected = '746865206b696420646f6e277420706c6179'
output = hexencode(xor_buffers(a, b))
assert(output == expected)
