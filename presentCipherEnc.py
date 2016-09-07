# !/usr/bin/env python3
# PRESENT crypto implementation
# 64 bit block & 80 bit key
# serhat

# PRESENT encryption Pseudocode
# generateRoundKeys()
# for i = 1 to 31 do
#     addRoundKey(state,Ki)
#     sBoxLayer(state)
#     pLayer(state)
# end for
# addRoundKey(state,K32)

# int(key, 16)  # hex string to decimal integer
# hex(dec)[2:]  # decimal integer to hex string


# TEST VECTORS
tKey = '00000000000000000000'  # 80 bit key for test
pText = '0000000000000000'  # 64 bit block plain text for encryption

roundKeyList = [0 for x in range(32)]

SBox = [0xC, 0x5, 0x6, 0xB, 0x9, 0x0, 0xA, 0xD, 0x3, 0xE, 0xF, 0x8, 0x4, 0x7, 0x1, 0x2]

PBox = [0, 16, 32, 48, 1, 17, 33, 49, 2, 18, 34, 50, 3, 19, 35, 51,
        4, 20, 36, 52, 5, 21, 37, 53, 6, 22, 38, 54, 7, 23, 39, 55,
        8, 24, 40, 56, 9, 25, 41, 57, 10, 26, 42, 58, 11, 27, 43, 59,
        12, 28, 44, 60, 13, 29, 45, 61, 14, 30, 46, 62, 15, 31, 47, 63]


def encrypt(plain_text, key):
    print('Plaintext: ' + plain_text)
    print('Key: ' + key + ' (80-bit)')

    # divide 80bits to 64bits + 16bits
    key_left = key[:-4]  # 64bits
    key_right = key[16:]  # 16bits

    cipher_text = 0
    state = int(plain_text, 16)  # hex string to integer
    # key = int(sKey, 16)          # hex string to integer
    key_left = int(key_left, 16)
    key_right = int(key_right, 16)

    generate_round_keys(key_left, key_right)
    for i in range(31):
        state = add_round_key(state, roundKeyList[i])
        state = s_box_layer(state)
        state = p_layer(state)
        print('Round Output ' + str(i + 1) + ': ' + dec_to_hex_str(state))
    cipher_text = add_round_key(state, roundKeyList[31])
    print('Ciphertext: ' + dec_to_hex_str(cipher_text))


def generate_round_keys(key_left, key_right):
    # input: 80-bit key
    # output: list of 64-bit round keys

    # K1...K32
    for i in range(32):
        # Ki = k79k78...k16
        roundKeyList[i] = key_left
        print('Round key ' + str(i + 1) + ': ' + dec_to_hex_str(roundKeyList[i]))

        # [k79k78...k1k0] = [k18k17...k20k19]
        # rotate RIGHT 19 bits (shift and append)
        temp_right = key_right
        key_right = (key_left >> 3) & 0xffff
        key_left = (key_left << 61) | (temp_right << 45) | (key_left >> 19)

        # [k79k78k77k76] = S[k79k78k77k76]
        temp_left = key_left
        key_left = (SBox[(temp_left >> 60) & 0xf] << 60)
        key_left |= (temp_left & 0x0fffffffffffffff)

        # [k19k18k17k16k15] = [k19k18k17k16k15] XOR round_counter
        r_counter = (i + 1) & 0x1f
        key_left ^= r_counter >> 1
        key_right ^= (r_counter & 0x1) << 15


def add_round_key(state, round_key):
    return state ^ round_key


# state = w15...w0 where wi = b4i+3||b4i+2||b4i+1||b4i for 0≤i≤15
def s_box_layer(state):
    s_state = 0
    for i in range(16):
        s_state |= SBox[(state >> 4 * i) & 0xf] << (4 * i)
    return s_state


def p_layer(state):
    p_state = 0
    for i in range(64):
        p_state |= ((state >> i) & 0x1) << PBox[i]
    return p_state


# fill left side with 0s
def dec_to_hex_str(dec):
    hex_str = hex(dec)[2:]
    for i in range(16 - len(hex(dec)[2:])):
        hex_str = '0' + hex_str
    return hex_str


if __name__ == "__main__":
    encrypt(pText, tKey)
