# Part4-ECDSA-from-the-scratch

The following implementation is intended to illustrate the implementation of ECDSA and is not intended for production use.

Elliptic curves are described by the [general Weierstrass equation][i_1]:

```
y^2 + a1*x*y + a3*y = x^3 + a2*x^2 + a4*x + a6 
```

which under certain conditions can be converted into the [short Weierstrass equation][i_1]:

```
y^2 = x^3 + Ax + B
```

The elliptic curves over finite fields Fp used in the context of ECDSA/ECDH are described by the short Weierstrass equation (note that there are also elliptic curves over finite fields F2m which are not considered here, see [here][i_2]). 

For completeness: [Alternative representations][i_3] of elliptic curves relevant in the context of cryptography are the Montgomery curve (X25519) and the Twisted Edwards curve (Ed25519).

[SEC 2: Recommended Elliptic Curve Domain Parameters][4] gives an overview of the different curves used in the context of ECDSA/ECDH.

In this post *secp256k1* is used, with the following parameters:

```
y^2 = x^3 + ax + b
p: 		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F    # prime number of finite field (Gallois field) Fp
a:	 	0
b:	 	7
Gx:		0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798")  # x coodinate of generator point G
Gy:		0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8")  # y coodinate of generator point G
n:		0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141")  # order of generator point G
h:		1                                                                     # cofactor
```

---------------

**Part 1: Point addition**

Point addition and doubling with affine and projective coordinates are described e.g. in [Elliptic curve point addition in projective coordinates, Arithmetic in affine coordinates][1_5], [Wikipedia, Elliptic curve, Algebraic interpretation][1_6], [Wikibooks, Cryptography/Prime Curve/Standard Projective Coordinates][1_7]. 

The formulas with the affine coordinates contain modular divisions, which are slow. The formulas with the projective coordinates are more complex and contain more operations, but no modular divisions, which is why they are more performant overall. Because of the large scalars in point multiplication, many point additions and point doublings are carried out, which is why the performance gain due to the projective coordinates is multiplied. Therefore, the projective coordinates are used in practice.

In *100_point_addition.py* the point addition and doubling in affine and projective coordinates and the transformation between both coordinate systems is implemented. Tests are also included for both coordinate systems. 

--------------

**Part 2: Point multiplication**

For point multiplication, the [Montgomery ladder][2_1] is used. The Montgomery ladder is time constant, since a fixed number of bits is used for each scalar (of the size of the order of the generator point) and identical operations are performed for 0- and 1-bits.

For the point addition and doubling used by the Montgomery Ladder, the projective coordinates are applied.

*200_point_multiplication.py* implements point multiplication and some tests.

--------------

**Part 3: Point compression**

A public EC key is an EC point. 

A possible format of a public key is the uncompressed format. This consists of the concatenation of the marker byte 0x04 and x and y coordinates, concerning the last two each as byte sequence in big endian order, if necessary padded from the front with 0x00 values to the size of the order of the generator point. 

Besides there is the compressed format, which consists of the concatenation of a marker byte and the x coordinate. The marker byte is 0x02 if y is even or 0x03 if it is odd. 
This information is complete, i.e. sufficient to reconstruct the y coordinate. If x is substituted into the short Weierstrass equation, the solution is the two values y and p-y, one of which is even and one odd. The marker byte can be used to identify the matching solution. In this way, the uncompressed key is reconstructed from the compressed key.

In the case of secp256k1, the size of the order of the generator point is 32 bytes, so an uncompressed key is 1+2*32=65 bytes in size and a compressed 1+32=33 bytes.

The compression and uncompression including tests is implemented in *300_point_compression.py*. Note that for the determination of y and p-y it was exploited that for secp256k1 the modulus is congruent to 3 modulus 4 and therefore [this solution path][3_1] was used. In case of a generalization to arbitrary curves, the other solution paths have to be considered/implemented if necessary. 

[i_1]: https://planetmath.org/weierstrassequationofanellipticcurve
[i_2]: https://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc#elliptic-curves-over-finite-fields
[i_3]: https://en.wikipedia.org/wiki/Elliptic_curve#Alternative_representations_of_elliptic_curves
[i_4]: https://www.secg.org/sec2-v2.pdf
[1_5]: https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
[1_6]: https://en.wikipedia.org/wiki/Elliptic_curve#Algebraic_interpretation
[1_7]: https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates
[2_1]: https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication#Montgomery_ladder
[3_1]: https://www.rieselprime.de/ziki/Modular_square_root#Modulus_congruent_to_3_modulo_4

