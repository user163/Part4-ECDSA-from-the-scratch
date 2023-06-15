# secp256k1 curve parameters
p_bytes = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F") # prime number of finite field (Gallois field) Fp
p = int.from_bytes(p_bytes, 'big')
a = 0
b = 7
Gx_bytes = bytes.fromhex("79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798") # x coodinate of generator point
Gx = int.from_bytes(Gx_bytes, 'big')
Gy_bytes = bytes.fromhex("483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8") # y coodinate of generator point
Gy = int.from_bytes(Gy_bytes, 'big')
n_bytes = bytes.fromhex("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141") # order of G
n = int.from_bytes(n_bytes, 'big')
size_order = (n.bit_length() + 7) // 8                                                      # size of order in bytes
h = 1 # cofactor

'''
_2   affine
_3   projective
     number
_b   bytes
e.g. P_2b:   affine coordinates in bytes 
     P_2:    affine coordinates in numbers
     n:      number 
     n_b:    bytes
'''

def affine_to_uncompressed(P_2b):
    (px_b, py_b) = P_2b
    return b'\x04' + px_b + py_b

def uncompressed_to_affine(uncompressed_b):
    px_b = uncompressed_b[1:size_order+1]
    py_b = uncompressed_b[size_order+1:]
    return (px_b, py_b)

def number_to_bytes(s):
    return int.to_bytes(s, size_order, 'big')

def bytes_to_number(s_b):
    return int.from_bytes(s_b, 'big')

def point_number_to_bytes(P_2):
    (px, py) = P_2
    return (number_to_bytes(px), number_to_bytes(py))

def point_bytes_to_number(P_2b):
    (px_b, py_b) = P_2b
    return (bytes_to_number(px_b), bytes_to_number(py_b))

def compress(uncompressed_b):
    px_b = uncompressed_b[1:size_order+1]
    py_b = uncompressed_b[size_order+1:]
    py = bytes_to_number(py_b)
    marker_b = b'\x03' if py & 1 else b'\x02'
    return marker_b + px_b

def uncompress(compressed_b):
    if (p - 3) % 4 != 0: # https://www.rieselprime.de/ziki/Modular_square_root
        raise Exception("Modulus not congruent to 3 modulo 4: uncompressing not implemented") 
    marker_b = compressed_b[0]
    px_b = compressed_b[1:]
    px = bytes_to_number(px_b)
    py_candidate = pow(pow(px, 3, p) + a * px + b, (p + 1) // 4, p)
    if py_candidate & 1 == (marker_b == b'\x03'):
        py = py_candidate
    else:
        py = (p - py_candidate) % p
    py_b = number_to_bytes(py)
    return b'\x04' + px_b + py_b
  
G_2b = (Gx_bytes, Gy_bytes)
res1_G_uncompressed_2b = affine_to_uncompressed(G_2b)
res2_G_2b = uncompressed_to_affine(res1_G_uncompressed_2b) 
res3_G_compressed_b = compress(res1_G_uncompressed_2b)
res4_G_uncompressed_b = uncompress(res3_G_compressed_b)
print(res1_G_uncompressed_2b.hex())
print(res2_G_2b[0].hex())
print(res2_G_2b[1].hex())
print(res3_G_compressed_b.hex())
print(res4_G_uncompressed_b.hex())

print()

input_6G_2b = (bytes.fromhex('FFF97BD5755EEEA420453A14355235D382F6472F8568A18B2F057A1460297556'), bytes.fromhex('AE12777AACFBB620F3BE96017F45C560DE80F0F6518FE4A03C870C36B075F297'))
res5_6G_uncompressed_2b = affine_to_uncompressed(input_6G_2b)
res6_6G_2b = uncompressed_to_affine(res5_6G_uncompressed_2b) 
res7_6G_compressed_b = compress(res5_6G_uncompressed_2b)
res8_6G_uncompressed_b = uncompress(res7_6G_compressed_b)
print(res5_6G_uncompressed_2b.hex())
print(res6_6G_2b[0].hex())
print(res6_6G_2b[1].hex())
print(res7_6G_compressed_b.hex())
print(res8_6G_uncompressed_b.hex())