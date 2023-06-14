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
h = 1 # cofactor

# from previous chapters ############################################################################

# _3 denotes projective coordinates

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

# new ###############################################################################################

# Montgomery Ladder, time constant for scalars up to size_order * 8 bits
def point_multiplication(s, P):
    size_order = (n.bit_length() + 7) // 8        # size of order in bytes
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

#
# test:
#

'''
reference values from https://asecuritysite.com/encryption/secp256k1p?n=5
0G      : None
1G      : (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)
6G      : (115780575977492633039504758427830329241728645270042306223540962614150928364886, 78735063515800386211891312544505775871260717697865196436804966483607426560663)
1000000G: (79313901484914205213801568353117391814503318608299263551128055406836608939724, 89820992854657193220054246803891283834085494543705029541431436389695328624353)
(n-1)G  : (55066263022277343669578718895168534326250603453777594175500187360389116729240, 83121579216557378445487899878180864668798711284981320763518679672151497189239)
nG      : None
(n+1)G  : (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)
'''

G_2 = (Gx, Gy)
res1_0G_3 = point_multiplication(0, affine_to_projective(G_2))
res2_1G_3 = point_multiplication(1, affine_to_projective(G_2))
res3_6G_3 = point_multiplication(6, affine_to_projective(G_2))
res4_xG_3 = point_multiplication(1000000, affine_to_projective(G_2))
res5_mG_3 = point_multiplication(n - 1, affine_to_projective(G_2))
res6_nG_3 = point_multiplication(n, affine_to_projective(G_2))
res7_oG_3 = point_multiplication(n + 1, affine_to_projective(G_2))
print("0G      : " + str(projective_to_affine(res1_0G_3)))
print("1G      : " + str(projective_to_affine(res2_1G_3)))
print("6G      : " + str(projective_to_affine(res3_6G_3)))
print("1000000G: " + str(projective_to_affine(res4_xG_3)))
print("(n-1)G  : " + str(projective_to_affine(res5_mG_3)))
print("nG      : " + str(projective_to_affine(res6_nG_3)))
print("(n+1)G  : " + str(projective_to_affine(res7_oG_3)))
