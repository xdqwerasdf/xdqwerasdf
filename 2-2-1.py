key = bytes(random_key(16))
random_prefix = random_key(randint(0, 256))

def encryption_oracle(data):
    unknown_string = bytearray((
        "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg\n" +
        "aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq\n" +
        "dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg\n" +
        "YnkK"
    ).decode("base64"))
    plaintext = pad_pkcs7(
        random_prefix + data + unknown_string,
        AES.block_size,
    )
    return aes_128_ecb_enc(plaintext, key)

def get_prefix_size(oracle, block_size):
    for prefix_padding_size in range(block_size):
        reps = 10
        prefix_padding = bytearray("A" * prefix_padding_size)
        buffer = oracle(prefix_padding + bytearray("YELLOW SUBMARINE" * reps))
        prev_block = count = index = None
        for i in range(0, len(buffer), block_size):
            block = buffer[i: i + block_size]
            if block == prev_block:
                count += 1
            else:
                index = i
                prev_block = block
                count = 1

            if count == reps:
                return index, prefix_padding_size

def get_unknown_string(oracle):
    block_size = get_block_size(oracle)
    prefix_size_rounded, prefix_padding_size = get_prefix_size(oracle, block_size)
    unknown_string_size = (
        get_unknown_string_size(oracle) -
        prefix_size_rounded -
        prefix_padding_size
    )

    unknown_string = bytearray()
    unknown_string_size_rounded = (
        ((unknown_string_size / block_size) + 1) *
        block_size
    )
    for i in range(unknown_string_size_rounded - 1, 0, -1):
        d1 = bytearray("A" * (i + prefix_padding_size))
        c1 = oracle(d1)[
            prefix_size_rounded:
            unknown_string_size_rounded + prefix_size_rounded
        ]
        for c in range(256):
            d2 = d1[:] + unknown_string + chr(c)
            c2 = oracle(d2)[
                prefix_size_rounded:
                unknown_string_size_rounded + prefix_size_rounded
            ]
            if c1 == c2:
                unknown_string += chr(c)
                break
    return unknown_string

get_unknown_string(encryption_oracle)