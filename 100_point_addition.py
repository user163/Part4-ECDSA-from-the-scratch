# Weierstass curve: y^2 = x^3 + a * x + b
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

# _2 denotes affine coodinates

def affine_add(p_2, q_2):
    if p_2 == q_2:
        return affine_double(p_2)
    elif p_2 == None: 
        return q_2 
    elif q_2 == None: 
        return p_2
    else:
        (px, py) = p_2
        (qx, qy) = q_2
        if px == qx: 
            return None # py != qy
        else:
            s_numerator = (py - qy) % p
            s_denominator = pow(px - qx, -1, p) # px != qx
            s = (s_numerator * s_denominator) % p
            rx = (pow(s, 2, p) - px - qx) % p
            ry = (s * (px - rx) - py) % p
            return (rx, ry)

def affine_double(p_2):
    if (p_2 == None):
        return None
    else:
        (px, py) = p_2
        if py == 0:
            return None
        else:
            s_numerator = (3 * pow(px, 2, p) + a) % p
            s_denominator = pow(2 * py, -1, p) # y != 0
            s = (s_numerator * s_denominator) % p
            rx = (pow(s, 2, p) - 2 * px) % p
            ry = (s * (px - rx) - py) % p
            return (rx, ry)

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

#
# test: affine coordinates
#
'''
# reference values from https://asecuritysite.com/encryption/secp256k1p?n=5
G:     (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)
0+0:   None
G+0:   (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)
0+G:   (55066263022277343669578718895168534326250603453777594175500187360389116729240, 32670510020758816978083085130507043184471273380659243275938904335757337482424)
2G:    (89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)
2G+G:  (112711660439710606056748659173929673102114977341539408544630613555209775888121, 25583027980570883691656905877401976406448868254816295069919888960541586679410)
2*2G:  (103388573995635080359749164254216598308788835304023601477803095234286494993683, 37057141145242123013015316630864329550140216928701153669873286428255828810018)
3G+2G: (21505829891763648114329055987619236494102133314575206970830385799158076338148, 98003708678762621233683240503080860129026887322874138805529884920309963580118)
4G+G:  (21505829891763648114329055987619236494102133314575206970830385799158076338148, 98003708678762621233683240503080860129026887322874138805529884920309963580118)
2*3G:  (115780575977492633039504758427830329241728645270042306223540962614150928364886, 78735063515800386211891312544505775871260717697865196436804966483607426560663)
0G:    None
2G:    (89565891926547004231252920425935692360644145829622209833684329913297188986597, 12158399299693830322967808612713398636155367887041628176798871954788371653930)
2*2G:  (103388573995635080359749164254216598308788835304023601477803095234286494993683, 37057141145242123013015316630864329550140216928701153669873286428255828810018)
2*3G:  (115780575977492633039504758427830329241728645270042306223540962614150928364886, 78735063515800386211891312544505775871260717697865196436804966483607426560663)
'''
G_2 = (Gx, Gy)
res1_0G_2 = affine_add(None, None) # calls implicitly affine_double
res2_1G_2 = affine_add(G_2, None)
res3_1G_2 = affine_add(None, G_2)
res4_2G_2 = affine_add(G_2, G_2)  # calls implicitly affine_double
res5_3G_2 = affine_add(res4_2G_2, G_2)
res6_4G_2 = affine_add(res4_2G_2, res4_2G_2)  # calls implicitly affine_double
res7_5G_2 = affine_add(res5_3G_2, res4_2G_2)
res8_5G_2 = affine_add(res6_4G_2, res3_1G_2)
res9_6G_2 = affine_add(res5_3G_2, res5_3G_2)  # calls implicitly affine_double

res13_0G_2 = affine_double(None)
res10_2G_2 = affine_double(G_2)
res11_4G_2 = affine_double(res4_2G_2)
res12_6G_2 = affine_double(res5_3G_2)

print("G:     " + str(G_2))
print("0+0:   " + str(res1_0G_2))
print("G+0:   " + str(res2_1G_2))
print("0+G:   " + str(res3_1G_2))
print("2G:    " + str(res4_2G_2))
print("2G+G:  " + str(res5_3G_2))
print("2*2G:  " + str(res6_4G_2))
print("3G+2G: " + str(res7_5G_2))
print("4G+G:  " + str(res8_5G_2))
print("2*3G:  " + str(res9_6G_2))

print("0G:    " + str(res13_0G_2))
print("2G:    " + str(res10_2G_2))
print("2*2G:  " + str(res11_4G_2))
print("2*3G:  " + str(res12_6G_2))

print()

#
# test: projective coordinates
#
G_2 = (Gx, Gy)
G_3 = affine_to_projective(G_2)
res13_0G_3 = projective_add(None, None)
res14_1G_3 = projective_add(G_3, None)
res15_1G_3 = projective_add(None, G_3)
res16_2G_3 = projective_add(G_3, G_3)
res17_3G_3 = projective_add(res16_2G_3, G_3)
res18_4G_3 = projective_add(res16_2G_3, res16_2G_3)
res19_5G_3 = projective_add(res17_3G_3, res16_2G_3)
res20_5G_3 = projective_add(res18_4G_3, res15_1G_3)
res21_6G_3 = projective_add(res17_3G_3, res17_3G_3)

res22_0G_3 = projective_double(None)
res23_2G_3 = projective_double(G_3)
res24_4G_3 = projective_double(res16_2G_3)
res25_6G_3 = projective_double(res17_3G_3)

print("0+0:   " + str(projective_to_affine(res13_0G_3)))
print("G+0:   " + str(projective_to_affine(res14_1G_3)))
print("0+G:   " + str(projective_to_affine(res15_1G_3)))
print("2G:    " + str(projective_to_affine(res16_2G_3)))
print("2G+G:  " + str(projective_to_affine(res17_3G_3)))
print("2*2G:  " + str(projective_to_affine(res18_4G_3)))
print("3G+2G: " + str(projective_to_affine(res19_5G_3)))
print("4G+G:  " + str(projective_to_affine(res20_5G_3)))
print("2*3G:  " + str(projective_to_affine(res21_6G_3)))

print("0G:    " + str(projective_to_affine(res22_0G_3)))
print("2G:    " + str(projective_to_affine(res23_2G_3)))
print("2*2G:  " + str(projective_to_affine(res24_4G_3)))
print("2*3G:  " + str(projective_to_affine(res25_6G_3)))