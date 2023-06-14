# Part4-ECDSA-from-the-scratch

# Introduction
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

# Part 1: Point addition

[i_1]: https://planetmath.org/weierstrassequationofanellipticcurve
[i_2]: hhttps://cryptobook.nakov.com/asymmetric-key-ciphers/elliptic-curve-cryptography-ecc#elliptic-curves-over-finite-fields
[i_3]: https://en.wikipedia.org/wiki/Elliptic_curve#Alternative_representations_of_elliptic_curves
[i_4]: https://www.secg.org/sec2-v2.pdf
[5]: https://www.nayuki.io/page/elliptic-curve-point-addition-in-projective-coordinates
[6]: https://en.wikipedia.org/wiki/Elliptic_curve#Algebraic_interpretation
[7]: https://en.wikibooks.org/wiki/Cryptography/Prime_Curve/Standard_Projective_Coordinates


