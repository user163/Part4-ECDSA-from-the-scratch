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

# from previous chapters ############################################################################

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

def projective_add(p_3, q_3):
    if p_3 == q_3:
        return projective_double(p_3)
    elif p_3 == None:
        return q_3
    elif q_3 == None:
        return p_3
    (px, py, pz) = p_3
    (qx, qy, qz) = q_3
    U1 = (qy * pz) % p
    U2 = (py * qz) % p
    V1 = (qx * pz) % p
    V2 = (px * qz) % p
    if V1 == V2:
        if U1 != U2:  
            return None
        #else:
        #    return projective_double(p_3) # corresponds to p_3 == q_3
    else:
        U = (U1 - U2) % p
        V = (V1 - V2) % p
        W = (pz * qz) % p
        A = (pow(U, 2, p) * W - pow(V, 3, p) - 2 * pow(V, 2, p) * V2) % p
        rx = (V * A) % p
        ry = (U * (pow(V, 2, p) * V2 - A) - pow(V, 3, p) * U2) % p
        rz = (pow(V, 3, p) * W) % p
        return (rx, ry, rz)

def projective_double(p_3):
    if p_3 == None:
        return None
    (px, py, pz) = p_3
    if py == 0:
        return None
    else:
        W = (a * pow(pz, 2, p) + 3 * pow(px, 2, p))
        S = (py * pz) % p
        B = (px * py * S) % p
        H = (pow(W, 2, p) - 8 * B) % p
        rx = (2 * H * S) % p
        ry = (W * (4 * B - H) - 8 * pow(py, 2, p) * pow(S, 2, p)) % p
        rz = (8 * pow(S, 3, p)) % p
        return (rx, ry, rz)

def affine_to_projective(P_2):
    if P_2 == None:
        return None
    (px, py) = P_2
    P_3 = (px, py, 1)
    return P_3

def projective_to_affine(P_3):
    if P_3 == None:
        return None
    (px, py, pz) = P_3
    pz_inv = pow(pz, -1, p)
    P_2 = ((px * pz_inv) % p, (py * pz_inv) % p)
    return P_2

# Montgomery Ladder, time constant for scalars up to size_order * 8 bits
def point_multiplication(s, P):
    Q = None                                      # neutral element
    bits = bin(s)[2:]                             # bit encoding of s
    bitsPadded = bits.rjust(size_order * 8, '0')  # the bit representation of all scalars is extended with leading 0 to 256 bit 
    for b in bitsPadded:                          # for each step, the same operations are done, no matter if the bit is 0 or 1
        if b == '0':
            P = projective_add(Q, P)
            Q = projective_double(Q)
        else:
            Q = projective_add(Q, P)
            P = projective_double(P)
    return Q

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
  
# new ###############################################################################################

import secrets

def create_keypair():
    secret_key = secrets.randbelow(n)
    secret_key_b = number_to_bytes(secret_key)
    G_3 = affine_to_projective((Gx, Gy))
    public_key_3 = point_multiplication(secret_key, G_3)
    public_key_2 = projective_to_affine(public_key_3)
    public_key_2b = point_number_to_bytes(public_key_2)
    return (secret_key_b, affine_to_uncompressed(public_key_2b))

(secret_key, public_key) = create_keypair()
print(secret_key.hex())
print(public_key.hex())
