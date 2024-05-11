def base_2b(s, b, out_len):
    """ Algorithm 3: base_2b (X, b, out_len).
        Compute the base 2**b representation of X."""
    i = 0               # in
    c = 0               # bits
    t = 0               # total
    v = []              # baseb
    m = (1 << b) - 1    # mask
    for j in range(out_len):
        while c < b:
            t = (t << 8) + int(s[i])
            i += 1
            c += 8
        c -= b
        v += [ (t >> c) & m ]
    return v


s = [0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0]
# Output: [1, 2, 3, 4]
print(base_2b(s, 4, 4))


s = [0x98, 0x76, 0x54, 0x32, 0x10]
# Output: [9, 8, 7, 6, 5, 4, 3, 2, 1, 0]
print(base_2b(s, 4, 10))
