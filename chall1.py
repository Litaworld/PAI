def xor_bytes(a, b):
    return bytes([x ^ y for x, y in zip(a, b)])

# diketaui (hex strings)
k1 = "3c3f0193af37d2ebbc50cc6b91d27cf61197"
k21 = "ff76edcad455b6881b92f726987cbf30c68c"
k23 = "611568312c102d4d921f26199d39fe973118"
k1234 = "91ec5a6fa8a12f908f161850c591459c3887"
f45 = "0269dd12fe3435ea63f63aef17f8362cdba8"

# konversi hex ke bytes
key1 = bytes.fromhex(k1)
k21_b = bytes.fromhex(k21)
k23_b = bytes.fromhex(k23)
k1234_b = bytes.fromhex(k1234)
f45_b = bytes.fromhex(f45)

# cari semua kunci
# k21 = KEY2 ^ KEY1  => KEY2 = k21 ^ KEY1
key2 = xor_bytes(k21_b, key1)

# k23 = KEY2 ^ KEY3  => KEY3 = k23 ^ KEY2
key3 = xor_bytes(k23_b, key2)

# k1234 = KEY4 ^ KEY1 ^ KEY3 ^ KEY2
# KEY4 = k1234 ^ KEY1 ^ KEY3 ^ KEY2
# lakukan XOR
tmp = xor_bytes(k1234_b, key1)
tmp = xor_bytes(tmp, key3)
key4 = xor_bytes(tmp, key2)

# isolasi FLAG ^ KEY5  (f45 = FLAG ^ KEY4 ^ KEY5 -> FLAG ^ KEY5 = f45 ^ KEY4)
flag_tmp = xor_bytes(f45_b, key4[:len(f45_b)])

# known-plaintext attack untuk mencari KEY5 (flag diawali dengan 'cry{')
known_plaintext = b'cry{'
key5 = xor_bytes(flag_tmp[:4], known_plaintext)

# perluas KEY5 agar panjangnya sama (repeating key)
full_key5 = (key5 * (len(flag_tmp) // len(key5) + 1))[:len(flag_tmp)]

# flag final (bytes)
flag = xor_bytes(flag_tmp, full_key5)
print(flag.decode())
