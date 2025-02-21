def h(n):
    # Return the hexadecimal representation of n without the "0x" prefix.
    return hex(n)[2:]


def extended_gcd(a, b):
    last_remainder, remainder = abs(a), abs(b)
    x, last_x = 0, 1
    y, last_y = 1, 0
    while remainder:
        last_remainder, (quotient, remainder) = remainder, divmod(last_remainder, remainder)
        x, last_x = last_x - quotient * x, x
        y, last_y = last_y - quotient * y, y
    return last_remainder, last_x * (-1 if a < 0 else 1), last_y * (-1 if b < 0 else 1)


def modinv(a, m):
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    return x % m


# Constants (interpreted as integers from hexadecimal literals)
N = 0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141
K = 0x7fffffffffffffffffffffffffffffff5d576e7357a4501ddfe92f46681b20a0
R = 0x00000000000000000000003b78ce563f89a0ed9414f5aa28ad0d96d6795f9c63
S = 0x0a963d693c008f0f8016cfc7861c7f5d8c4e11e11725f8be747bb77d8755f1b8
Z = 0x521a65420faa5386d91b8afcfab68defa02283240b25aeee958b20b36ddcb6de

# Compute the value:
# result = (((S * K) - Z) * modinv(R, N)) % N
result = (((S * K) - Z) * modinv(R, N)) % N

print(h(result))
