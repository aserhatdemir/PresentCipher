

# int(hexStr, 16)  # hex string to decimal integer
# hex(dec)[2:]  # decimal integer to hex string

tKey = '00000000000000000000'  # 80 bit key for test
pText = '0000000000000000'  # 64 bit block plain text for encryption

import base64
hex_data =''
ascii_string = str(base64.b16decode(hex_data))[2:-1]
print (ascii_string)

print(int('0000000000000010', 16))



print('pmp :(')
