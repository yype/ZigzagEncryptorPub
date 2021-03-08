import argparse


def bits_to_long(arr):
    result = 0
    for each in arr:
        result <<= 1
        result |= each
    return result


def bits_to_bytes(arr):
    result = []
    for i in range(len(arr)//8):
        tmp = 0
        for j in range(8):
            tmp = (tmp << 1) | arr[8*i+j]
        result.append(tmp)
    return result


def bytes_to_long(arr):
    num = 0
    for i in range(len(arr)):
        num |= (arr[-1-i] << (8*i))
    return num


def long_to_bits(num, size):
    result = []
    for _ in range(size):
        bit = num >> (size - 1)
        result.append(bit)
        num <<= 1
        num &= (1 << size) - 1
    return result


def get_original_bytes(message, order):
    order = int(order, 10)
    nums = [int(message[2*i:2*i+2], 16) for i in range(3)]

    orders = [[0, 1, 2],
              [0, 2, 1],
              [1, 0, 2],
              [1, 2, 0],
              [2, 0, 1],
              [2, 1, 0]]
    tmp = [0] * 3
    for idx in range(3):
        tmp[orders[order][idx]] = nums[idx]
    return tmp


def solve_mat_gf2(A, b, debug=False):
    if len(A) != len(b):
        print('Invalid matrix')
        exit(0)

    number_of_unk = len(A[0])

    _A = []
    for each in A:
        num = 0
        for bit in each:
            num = (num << 1) | bit
        _A.append(num)

    N = len(_A)

    def BIT(x, n): return (x >> (number_of_unk-1-n)) & 1

    if debug:
        for each in _A:
            print(bin(each)[2:].rjust(number_of_unk, '0'))
        print('')

    for i in range(number_of_unk):
        for j in range(i, N):
            if BIT(_A[j], i) == 1:
                _A[i], _A[j] = _A[j], _A[i]
                b[i], b[j] = b[j], b[i]
                break

        if BIT(_A[i], i) != 1:
            print('Solving error!')
            exit(0)
        for j in range(N):
            if j != i and BIT(_A[j], i) == 1:
                _A[j] ^= _A[i]
                b[j] ^= b[i]
    if debug:
        for each in _A:
            print(bin(each)[2:].rjust(number_of_unk, '0'))

    if 0 in _A[:number_of_unk]:
        print('Multiple solutions!')
        exit(0)

    return b[:number_of_unk]


def lfsr_gen_seq(init_vec, polynomial, number_of_bits):
    result = []
    for _ in range(number_of_bits):
        result.append(init_vec >> 127)
        tmp = init_vec & polynomial
        new_bit = 0
        for __ in range(128):
            new_bit ^= tmp & 1
            tmp >>= 1
        init_vec = ((init_vec << 1) | new_bit) & ((1 << 128)-1)

    return result


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "-i", "--input", help="Path to the encrypted svg pattern", required=True)
    args = parser.parse_args()
    svg_filename = args.input

    with open(svg_filename, 'r') as f:
        svg = f.read()

    idxes = [6752, 17999, 29058, 40115, 51174, 61856, 72393, 82935, 93584, 104197,
             114735, 125269, 135811, 146358, 156893, 167429, 177970, 188508, 199047, 209589,
             220127, 230668, 241212, 251752, 262294, 272839, 283381, 293925, 304470, 315009
             ]

    original_bytes = []
    for each in idxes:
        original_bytes += get_original_bytes(svg[each:each+6], svg[each+42])

    prefix = 'D^3CTF2021_SECURE_MESSAGE_PREFIX: '
    known_bytes = [ord(c) ^ original_bytes[idx]
                   for idx, c in enumerate(prefix)]

    lfsr_init_vector = known_bytes[:16]
    init_vec = bytes_to_long(lfsr_init_vector)

    known_bits = long_to_bits(bytes_to_long(known_bytes), len(known_bytes)*8)

    A = []
    # construct matrices A and b
    for i in range(len(known_bits)-128):
        A.append(known_bits[i:i+128])
    b = known_bits[128:]

    # [Reference] Berlekamp–Massey algorithm can be used to
    # solve this kind of problem directly. Here we just solve
    # the set of linear equations using Gaussian elimination.
    x = solve_mat_gf2(A, b, False)

    polynomial = bits_to_long(x)

    print(f'key:{polynomial},{init_vec}')

    key_bits = lfsr_gen_seq(init_vec, polynomial, len(original_bytes)*8)
    key_bytes = bits_to_bytes(key_bits)
    message = ''.join([chr(key_bytes[i] ^ original_bytes[i])
                       for i in range(len(original_bytes))
                    ]
              )

    print(f'message: {message}')


if __name__ == '__main__':
    main()
