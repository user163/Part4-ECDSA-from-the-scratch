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
  
import secrets
def create_keypair():
    secret_key = secrets.randbelow(n)
    secret_key_b = number_to_bytes(secret_key)
    G_3 = affine_to_projective((Gx, Gy))
    public_key_3 = point_multiplication(secret_key, G_3)
    public_key_2 = projective_to_affine(public_key_3)
    public_key_2b = point_number_to_bytes(public_key_2)
    return (secret_key_b, affine_to_uncompressed(public_key_2b))

# new ###############################################################################################

#
# signing
#
import hashlib
def ecdsa_sign(data_b, private_key_b, digest_name):
    # step 1: calculate message hash
    digest = hashlib.new(digest_name)
    digest.update(data_b)
    message_hash_b = digest.digest()
    message_hash = bytes_to_number(message_hash_b)
    # step 2: generate random k
    k = secrets.randbelow(n)
    # step 3: calculate random point R = k * G
    G_3 = affine_to_projective((Gx, Gy))
    R_3 = point_multiplication(k, G_3)
    R_2 = projective_to_affine(R_3)
    r = R_2[0]
    # step 4: calculate signature proof
    k_inv = pow(k, -1, n)
    s = (k_inv * (message_hash + r * bytes_to_number(private_key_b))) % n
    # step 5: return r|s
    return number_to_bytes(r) + number_to_bytes(s)

def ecdsa_verify(signature_b, data_b, public_key_b, digest_name):
    # step 1: calculate message hash
    digest = hashlib.new(digest_name)
    digest.update(data_b)
    message_hash_b = digest.digest()
    message_hash = bytes_to_number(message_hash_b)
    # step 2: calculate s^-1
    r_b = signature_b[:size_order]
    s_b = signature_b[size_order:]
    r = bytes_to_number(r_b)
    s = bytes_to_number(s_b)
    s_inv = pow(s, -1, n)
    # step 3:recover R
    G_3 = affine_to_projective((Gx, Gy))
    public_key_3 = affine_to_projective(point_bytes_to_number(uncompressed_to_affine(public_key_b)))
    TMP1_3 = point_multiplication(message_hash * s_inv, G_3)
    TMP2_3 = point_multiplication(r * s_inv, public_key_3)
    R_rec_3 = projective_add(TMP1_3, TMP2_3)
    R_rec_2 = projective_to_affine(R_rec_3)
    r_rec = R_rec_2[0]
    # step 4: return r == r_rec
    return r == r_rec

#
# test
#

(secret_key_b, public_key_b) = create_keypair()
data_b = b'The quick brown fox jumps over the lazy dog'
signature_b = ecdsa_sign(data_b, secret_key_b, 'sha256')
verified = ecdsa_verify(signature_b, data_b, public_key_b, 'sha256')

print("Sign with ecdsa_sign():     " + signature_b.hex())
print("Verify with ecdsa_verify(): " + str(verified))
print()

#
# Ckeck with PyCryptodome
#
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature, encode_dss_signature
from cryptography.exceptions import InvalidSignature
# test 1
# create signature with pyca/cryptography
x = int.from_bytes(public_key_b[1:size_order+1], "big")
y = int.from_bytes(public_key_b[size_order+1:], "big")
public = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256K1())
d = int.from_bytes(secret_key_b, "big")
private = ec.EllipticCurvePrivateNumbers(d, public).private_key()
signature_der_b = private.sign(data_b, ec.ECDSA(hashes.SHA256()))
signature_rs = decode_dss_signature(signature_der_b)
signature_rs_b = number_to_bytes(signature_rs[0]) + number_to_bytes(signature_rs[1])
# verify with ecdsa_verify
verified = ecdsa_verify(signature_rs_b, data_b, public_key_b, 'sha256')
print("Sign with pyca/cryptography: " + signature_rs_b.hex())
print("Verify with ecdsa_verify():  " + str(verified))
print()

# test 2
# create signature with ecdsa_sign
signature_rs_b = ecdsa_sign(data_b, secret_key_b, 'sha256')  
print("Sign with ecdsa_sign():        " + signature_rs_b.hex())
# verify signature with pyca/cryptography
r = bytes_to_number(signature_rs_b[:size_order])
s = bytes_to_number(signature_rs_b[size_order:])
signature_der_b = encode_dss_signature(r, s)
try:
    public.public_key().verify(signature_der_b, data_b, ec.ECDSA(hashes.SHA256()))
    print("Verfiy with pyca/cryptography: True")
except InvalidSignature:
    print("Verfiy with pyca/cryptography: False")