---
title: "Hybrid key exchange in JOSE and COSE"
abbrev: "Hybrid key exchange in JOSE and COSE"
category: std

docname: draft-ra-cose-hybrid-encrypt
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "COSE"
keyword:
 - PQC
 - COSE
 - JOSE
 - Hybrid

 

venue:
  group: "cose"
  type: "Working Group"
  mail: "cose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/cose/"
  

stand_alone: yes
pi: [toc, sortrefs, symrefs, strict, comments, docmapping]

author:
 -
    fullname: Tirumaleswar Reddy
    organization: Nokia
    city: Bangalore
    region: Karnataka
    country: India
    email: "kondtir@gmail.com"
 -
    fullname: Aritra Banerjee
    organization: Nokia
    city: Munich
    country: Germany
    email: "aritra.banerjee@nokia.com"

 
normative:

informative:
 
  SP800-56C:
     title: "Recommendation for Key-Derivation Methods in Key-Establishment Schemes"
     target: https://doi.org/10.6028/NIST.SP.800-56Cr2
     date: false
  SP800-185:
     title: "SHA-3 Derived Functions: cSHAKE, KMAC, TupleHash, and ParallelHash"
     target: https://doi.org/10.6028/NIST.SP.800-185
     date: false
  PQCAPI:
     title: "PQC - API notes"
     target: https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/example-files/api-notes.pdf
     date: false
  FO:
     title: "Secure Integration of Asymmetric and Symmetric Encryption Schemes"
     target: https://link.springer.com/article/10.1007/s00145-011-9114-1
     date: false
  HHK:
     title: "A Modular Analysis of the Fujisaki-Okamoto Transformation"
     target: https://link.springer.com/chapter/10.1007/978-3-319-70500-2_12
     date: false

     
--- abstract

Hybrid key exchange refers to using multiple key exchange algorithms simultaneously and combining the result with the goal of providing
security even if all but one of the component algorithms is broken. It is motivated by transition to post-quantum cryptography. 
This document provides a construction for hybrid key exchange in JOSE and COSE. It defines the use of traditional and PQC algorithms, 
a hybrid post-quantum KEM, for JOSE and COSE. 


--- middle

# Introduction

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. {{?I-D.ietf-pquip-pqt-hybrid-terminology}} defines terminology for the Post-Quantum and Traditional Hybrid Schemes.

This document gives a construction for hybrid key exchange in Javascript Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE). The overall design approach is a simple, "hash and concatenation" based approach to use a “hybrid” shared secret.

# Conventions and Definitions

{::boilerplate bcp14-tagged}
This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional Algorithm":  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms or elliptic curve discrete logarithms. In the context of JOSE, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman Ephemeral Static {{?RFC6090}} {{?RFC8037}}. In the context of COSE, examples of traditional key exchange algorithms include Ephemeral-Static (ES) DH and Static-Static (SS) DH {{?RFC9052}}. 

"Post-Quantum Algorithm":  An asymmetric cryptographic algorithm that is believed to be secure against attacks using quantum computers as well as classical computers. Examples of PQC key exchange algorithms include Kyber.

"Hybrid" key exchange, in this context, means the use of two key exchange algorithms based on different cryptographic assumptions, e.g., one traditional algorithm and one Post-Quantum
algorithm, with the purpose of the final shared secret key being secure as long as at least one of the component key exchange algorithms remains unbroken. It is referred to
as PQ/T Hybrid Scheme in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. 

PQ/T Hybrid Key Encapsulation Mechanism:  A Key Encapsulation mechanism (KEM) made up of two or more component KEM algorithms where at least one is a post-quantum algorithm and at least one is a traditional algorithm.

## Key Encapsulation Mechanisms

For the purposes of this document, we consider a Key Encapsulation Mechanism (KEM) to be any asymmetric cryptographic scheme comprised of algorithms satisfying the following interfaces [PQCAPI].  

* def kemKeyGen() -> (pk, sk)
* def kemEncaps(pk) -> (ct, ss)
* def kemDecaps(ct, sk) -> ss

where pk is public key, sk is secret key, ct is the ciphertext representing an encapsulated key, and ss is shared secret.

KEMs are typically used in cases where two parties, hereby refereed to as the "encapsulater" and the "decapsulater", wish to establish a shared secret via public key cryptography, where the decapsulater has an asymmetric key pair and has previously shared the public key with the encapsulater.
  
# Construction

Building a PQ/T hybrid KEM requires a secure function which combines the output of both component KEMs to form a single output.  Several IETF protocols are adding PQ/T hybrid KEM mechanisms as part of their overall post-quantum migration strategies, examples include TLS 1.3 {{?I-D.ietf-tls-hybrid-design}}, IKEv2 {{?RFC9370}}.

The migration to PQ/T Hybrid KEM calls for performing multiple key encapsulations in parallel and then combining their outputs to derive a single shared secret. It is compatible with NIST SP 800-56Cr2 [SP800-56C] when viewed as a key derivation function. The hybrid scheme defined in this document is the combination of Traditional and Post-Quantum Algorithms. The Key agreement Traditional and Post-Quantum Algorithms are used in parallel to generate shared secrets. The two shared secrets are hashed and concatenated together and used as the shared secret in JOSE and COSE. 

The JSON Web Algorithms (JWA) {{?RFC7518}} in Section 4.6 defines two ways using the key agreement result. When Direct Key Agreement is employed, the shared secret established through the ECDH algorithm will be the content encryption key (CEK). When Key Agreement with Key Wrapping is employed, the shared secret established through the ECDH algorithm will wrap the CEK. Simiarly, COSE in Sections 8.5.4 and 8.5.5 {{?RFC9052}} define the Direct Key Agreement and Key Agreement with Key Wrap classes. If multiple recipients are needed, then the version with key wrap is used.

It is essential to note that in the PQ/T hybrid KEM mode, one needs to apply Fujisaki-Okamoto {{FO}} transform or its variant {{HHK}} on the PQC KEM part to ensure that the overall scheme is IND-CCA2 secure as mentioned in {{?I-D.ietf-tls-hybrid-design}}. The FO transform is performed using the KDF such that the PQC KEM shared secret achieved is IND-CCA2 secure. In this case, one can re-use the PQC KEM public keys but depending on some upper bound that must adhered to.

# KEM Combiner {#kem-combiner}

The specification uses the KEM combiner defined in {{?I-D.ounsworth-cfrg-kem-combiners}} that takes in two or more shared secrets and returns a combined shared secret. In case of PQ/T Hybrid KEM, the shared secrets are the output of the traditional key exchange (Key Agreement with Elliptic Curve Diffie-Hellman Ephemeral Static defined in Section 4.6 of {{?RFC9370}} for JOSE and Key Agreement with Ephemeral-Static (ES) Diffie-Hellman (DH) defined in Section 6.3.1 of {{?RFC9053}} for COSE) and PQC KEM. The KEM combiner function is defined in Section 3 of {{?I-D.ounsworth-cfrg-kem-combiners}}. The KDF and Hash functions will be KMAC and SHA3 and the counter will be initialized with a value of 0x00000001 (Section 4 of {{?I-D.ounsworth-cfrg-kem-combiners}}). The KMAC functions used with the PQ/T hybrid algorithms are specified in the table below:

            +==============+=========+=========+
            | PQ/T hybrid algorithm  | KDF     |
            +========================+=========+
            | x25519-ES_kyber512     | KMAC256 |
            +------------------------+---------+
            | secp384r1-ES_kyber768  | KMAC256 |
            +------------------------+---------+
            | x25519-ES_kyber768     | KMAC256 |
            +-----------------------+----------+
            | secp256r1-ES_kyber512 |  KMAC256 |
            +------------------------+---------+

                             Table 1 


   KMAC is defined in NIST SP 800-56Cr2 [SP800-56C].  The KMAC(K, X, L, S) parameters are instantiated as follows:

   *  K: context-specific string. In case of JOSE, the context-specific string will be set to concat("JOSE_PostQuantum_Traditional_Hybrid", "_", Name of the PQ/T hybrid algorithm). In case of
      COSE, the context-specific string will be set to concat("COSE_PostQuantum_Traditional_Hybrid", "_", Name of the PQ/T hybrid algorithm). For example, 
      concat("JOSE_PostQuantum_Traditional_Hybrid", "_", "x25519-ES_kyber512") = "JOSE_PostQuantum_Traditional_Hybrid_x25519-ES_kyber512". Note: The maximum byte length of salt can be 132 bytes as discussed in Table 3 of [SP800-56C] but in our draft K is variable-length. The size of "K" will change based on the PQ/T hybrid algorithm. For instance, "x25519-ES_kyber512" and "secp256r1-ES_kyber512" will result in two different sizes of K after the concat operation. The application can either provide no salt and the K becomes the default salt or a shorter key K will be padded by appending an all-zero bit string to obtain a 132-byte output.

   *  X: concat(0x00000001, k_1, ... , k_n, fixedInfo). The fixedInfo parameter is a fixed-format string containing context-specific information.

   *  L: length of the output key in bits.

   *  S: utf-8 string "KDF".

In the case of a traditional key exchange algorithm (e.g., x25519, secp384r1) since there is no associated ciphertext present when calculating the constant-length input key (k1) defined in Section 3.2 of {{?I-D.ounsworth-cfrg-kem-combiners}}, the key derivation process defined in Section 4.6.2 of {{?RFC7518}} for JOSE would be used to construct k. However, in case of COSE, the HKDF (HMAC based Key Derivation Function) defined in Section 5 of {{?RFC9053}} would be used. The HKDF algorithm leverages HMAC SHA-256 as the underlying PRF (Pseudo-Random function) for secp256r1 and x25519, and HMAC SHA-384 for secp384r1. The context structure defined in Section 5.2 of {{?RFC9053}}, salt and secret from DH key agreement are used as inputs to the HKDF. In case of JOSE, the fixedInfo parameter will carry the JOSE context specific data defined 
in Section 4.6.2 of {{?RFC7518}}. In case of COSE, the fixedInfo parameter will carry the COSE context structure defined in Section 5.2 of {{?RFC9053}}. Note that the result of an ECDH key agreement process does not provide a uniformly random secret and it needs to be run through a KDF in order to produce a usable key (see Section 6.3.1 of {{?RFC9053}}).

The KEM combiner instantiation of the first entry of Table 1 would be:

      ss = KMAC256("COSE_PostQuantum_Traditional_Hybrid_X25519-ES_kyber512", "0x00000001 || 
                    HKDF-256(DH-Shared-Secret, salt, context) || 
                    ct_1 || rlen(ct_1) || ss_1 || rlen(ss_1) || context" , 256, "KDF")  

Where ss_1 is shared secret and its corresponding ciphertext ct_1 generated from kemEncaps(pk). If ss_1 or ct_1 are not guaranteed to have constant length, rlen encoded length is appended when concatenating as discussed in Section 3.2 of {{?I-D.ounsworth-cfrg-kem-combiners}}.

In Direct Key Agreement mode, the output of the KEM combiner MUST be a key of the same length as that used by encryption algorithm. In Key Agreement with Key Wrapping mode, the output of the KEM combiner MUST be a key of the length needed for the specified key wrap algorithm. 

# KEM PQC Algorithms

The National Institute of Standards and Technology (NIST) started a process to solicit, evaluate, and standardize one or more quantum-resistant public-key cryptographic algorithms, as seen [here](https://csrc.nist.gov/projects/post-quantum-cryptography). Said process has reached its [first announcement](https://csrc.nist.gov/publications/detail/nistir/8413/final) in July 5, 2022, which stated which candidates to be standardized for KEM:

* Key Encapsulation Mechanisms (KEMs): [CRYSTALS-Kyber](https://pq-crystals.org/kyber/): Kyber is a module learning with errors (MLWE)-based key encapsulation mechanism.

NIST announced as well that they will be [opening a fourth round](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/guidelines-for-submitting-tweaks-fourth-round.pdf) to standardize an alternative KEM, and a [call](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/call-for-proposals-dig-sig-sept-2022.pdf) for new candidates for a post-quantum signature algorithm.

## Kyber

Kyber offers several parameter sets with varying levels of security and performance trade-offs. This document specifies the use of the Kyber algorithm at two security levels: Kyber512 and Kyber768. Kyber key generation, encapsulation and decaspulation functions are defined in {{?I-D.cfrg-schwabe-kyber}}.

# Hybrid Key Representation with JOSE {#hybrid-kem}

The parameter "kty" MUST be present and set to "OKP" defined in Section 2 of {{?RFC7518}} for expressing the cryptographic keys for PQ/T Hybrid KEM, the following rules apply:

* The parameter "alg" MUST be specified, and its value MUST be one of the values specified in the table below:
  
              +===============================+===================================+
              | alg                           | Description                       |
              +===============================+===================================+
              | x25519-ES_kyber512            | Curve25519 elliptic curve +       |
              |                               | Kyber512 parameter                |
              |                               | Direct Key Agreement              |
              +===============================+===================================+
              | secp384r1-ES_kyber768         | P-384 + Kyber768 parameter        |
              |                               | Direct Key Agreement              |
              +===============================+===================================+
              | x25519-ES_kyber768            | Curve25519 elliptic curve +       |
              |                               | Kyber768 parameter                |
              |                               | Direct Key Agreement              |
              +===============================+===================================+
              | secp256r1-ES_kyber512         | P-256 +  Kyber512 parameter       |
              |                               | Direct Key Agreement              |
              +===============================+===================================+
              | x25519-ES_kyber512+A128KW     | Curve25519 elliptic curve +       |
              |                               | Kyber512 parameter + CEK wrapped  |
              |                               | with "A128KW"                     | 
              +========+==============---=====+===================================+
              | secp384r1-ES_kyber768+A128KW  | P-384 + Kyber768 parameter        |
              |                               |  + CEK wrapped with "A128KW"      |
              +========+===================+======================================+
              | x25519-ES_kyber768+A128KW     | Curve25519 elliptic curve +       |
              |                               | Kyber768 parameter + CEK wrapped  |
              |                               | with "A128KW"                     |
              +========+======================+===================================+
              | secp256r1-ES_kyber512+A128KW  | P-256 +  Kyber512 parameter       |
              |                               | + CEK wrapped with "A128KW"       |
              +===============================+===================================+
              | x25519-ES_kyber512+A256KW     | Curve25519 elliptic curve +       |
              |                               | Kyber512 parameter + CEK wrapped  |
              |                               | with "A256KW"                     | 
              +===============================+===================================+
              | secp384r1-ES_kyber768+A256KW  | P-384 + Kyber768 parameter        |
              |                               |  + CEK wrapped  with "A256KW"     |
              +===============================+===================================+
              | x25519-ES_kyber768+A256KW     | Curve25519 elliptic curve +       |
              |                               | Kyber768 parameter + CEK wrapped  |
              |                               | with "A256KW"                     |
              +===============================+===================================+
              | secp256r1-ES_kyber512+A256KW  | P-256 +  Kyber512 parameter       |
              |                               | + CEK wrapped with "A256KW"       |
              +===============================+===================================+

                                 Table 2
                      
* The parameter "kem" MUST be present and set to the PQC KEM algorithm.
* The parameter "kem-pk" MUST be present and contains the PQC KEM public key encoded using the base64url {{?RFC4648}} encoding.
* The parameter "kem-sk" MUST be present for private key and contains the PQC KEM private key encoded using the base64url encoding. This parameter MUST NOT be present for public key.
* The parameter "kem-ct" MUST be present for KEM ciphertext encoded using the base64url {{?RFC4648}} encoding. 
* The parameter "crv" MUST be present and contains the Elliptic Curve Algorithm used (from the "JSON Web Key Elliptic Curve" registry).
* The parameter "x" MUST be present and contains the x coordinate for the Elliptic Curve point encoded using the base64url {{?RFC4648}} encoding.
* The parameter "y" MUST be present and contains the y coordinate for the Elliptic Curve point encoded using the base64url {{?RFC4648}} encoding. This parameter is not present for "X25519".
* The parameter "d" MUST be present for private keys and contains the Elliptic Curve Algorithm private key encoded using the base64url encoding. This parameter MUST NOT be present for public keys.

In Table 2, "A128KW" and "A256KW" are AES Key Wrap with 128-bit key and 256-bit key respectively. Encryption of the plaintext is accomplished with AES symmetric key cryptography. In Table 2, 'ES' indicates that the traditional key agreement process is performed using an ephemeral key on the sender's side, and for each key agreement operation, the sender will generate a new ephemeral key.

The specification allows a small number of "known good" PQ/T hybrid algorithms listed in Table 2 instead of allowing arbitrary combinations of traditional and PQC algorithms. It follows the recent trend in protocols to only allow a small number of "known good" configurations that make sense, instead of allowing arbitrary combinations of individual configuration choices that may interact in dangerous ways. 

## "kem" {#kem}

The "kem" (KEM) parameter identifies PQC KEM algorithm used with the "kem-pk" key. KEM values used by this specification are:

      "kem"            PQC KEM Applied
      Kyber512            Kyber512          
      Kyber768            Kyber768

These values are registered in the IANA "JSON PQC KEM" registry defined in {{JSON-KEM-REGISTRY}}.  Additional "kem" values can be registered by other specifications.

## Example Hybrid Key Agreement Computation

   This example uses secp256r1-ES_kyber512, i.e., ECDH-ES Key Agreement with the P-256 curve and PQC KEM kyber512. 
   The KEM Combiner is used to derive the CEK in the manner described in {{kem-combiner}}.  
   In this example, the secp256r1_kyber512 Key Agreement mode ("alg" value "secp256r1_kyber512") 
   is used to produce an agreed-upon key for AES GCM with a 128-bit key ("enc"
   value "A128GCM").  

   In this example, a producer Alice is encrypting content to a consumer
   Bob.  The producer (Alice) generates an ephemeral key for the key
   agreement computation.  Alice's ephemeral key is used
   for the key agreement computation in this example (including the
   private part) is:

     {"kty":"OKP",
      "crv":"P-256",    
      "x":"alice_eph_public_key_x",
      "y":"alice_eph_public_key_y",
      "d":"alice_eph_private_key"
     }

   The consumer's (Bob's) key used for the key agreement computation 
   in this example (including the private part) is:

     {"kty":"OKP",
      "kem": "kyber512",
      "kem-pk":"bob_kyber_public_key",
      "kem-sk":"bob_kyber_private_key"
      "crv":"P-256",
      "x":"bob_public_key_x",
      "y":"bob_public_key_y",
      "d":"bob_private_key"
     }

   Header Parameter values used in this example are as follows.

     {"alg":"secp256r1-ES_kyber512",
      "enc":"A128GCM",
      "apu":"QWxpY2U",  // base64url encoding of the UTF-8 string "Alice"
      "apv":"Qm9i",    // base64url encoding of the UTF-8 string "Bob"
      "epk":
       {"kty":"OKP",
        "crv":"P-256",
        "x":"alice_eph_public_key_x",
        "y":"alice_eph_public_key_y",
       }
     }
   

# Hybrid Key Representation with COSE {#cose-hybrid-kem}

The approach taken here matches the work done to support secp256k1 in JOSE and COSE in {{?RFC8812}}. The following table maps terms between JOSE and COSE for Key Type Parameters.

        +======================+========================================+==+
        | Name                 | Value | Description                       |
        +======================+===========================================+
        | crv                  | -1    | EC used                           |
        +----------------------+-------------------------------------------+
        | d                    | -4    | Private key                       |
        +----------------------+-------------------------------------------+
        | x                    | -2    | x coordinate for the public key   |
        +----------------- ----+-------------------------------------------+
        | y                    | -3    | y coordinate for the public key   |
        +---------------- -----+-------------------------------------------+
        | kem                  | TBD2  | PQC KEM Algorithm                 |
        +----------------------+-------------------------------------------+
        | kem-pk               | TBD3  | PQC KEM Public Key                |
        +----------------------+-------------------------------------------+
        | kem-sk               | TBD4  | PQC KEM Private Key               |
        +----------------------+-------------------------------------------+
        | kem-ct               | TBD5  | PQC KEM ciphertext                |
        +----------------------+-------------------------------------------+

                                 Table 3

The following table maps terms between JOSE and COSE for PQ/T Hybrid KEM.

        +==============+===================+====================+============================+
        | Name                          | Value  | Description                 | Recommended |
        +===================+===========+========+=============================+=============+
        | x25519-ES_kyber512            | TBD10  | Curve25519 elliptic curve + | No          |
        |                               |        | Kyber512 parameter          |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | secp384r1-ES_kyber768         | TBD11  | P-384 + Kyber768 parameter  | No          |
        |                               |        |                             |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | x25519-ES_kyber768            | TBD12  | Curve25519 elliptic curve   | No          |
        |                               |        | + Kyber768 parameter        |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | secp256r1-ES_kyber512         | TBD13  | P-256 + Kyber512 parameter  | No          |
        |                               |        |                             |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | x25519-ES_kyber512+A128KW     | TBD14  | Curve25519 elliptic curve + | No          |
        |                               |        | Kyber512 parameter +        |             |
        |                               |        | CEK wrapped with "A128KW"   |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | secp384r1-ES_kyber768+A128KW  | TBD15  | P-384 + Kyber768 parameter  | No          |
        |                               |        | + CEK wrapped with "A128KW" |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | x25519-ES_kyber768+A128KW     | TBD16  | Curve25519 elliptic curve   | No          |
        |                               |        | + Kyber768 parameter        |             |
        |                               |        | + CEK wrapped with "A128KW" |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | secp256r1-ES_kyber512+A128KW  | TBD17  | P-256 + Kyber512 parameter  | No          |
        |                               |        | + CEK wrapped with "A128KW" |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | x25519-ES_kyber512+A256KW     | TBD18  | Curve25519 elliptic curve + | No          |
        |                               |        | Kyber512 parameter +        |             |
        |                               |        | CEK wrapped with "A256KW"   |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | secp384r1-ES_kyber768+A256KW  | TBD19  | P-384 + Kyber768 parameter  | No          |
        |                               |        | + CEK wrapped with "A256KW" |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | x25519-ES_kyber768+A256KW     | TBD20  | Curve25519 elliptic curve   | No          |
        |                               |        | + Kyber768 parameter        |             |
        |                               |        | + CEK wrapped with "A256KW" |             |
        +-------------------------------+--------+-----------------------------+-------------+
        | secp256r1_-ES_kyber512+A256KW | TBD21  | P-256 + Kyber512 parameter  | No          |
        |                               |        | + CEK wrapped with "A256KW" |             |
        +-------------------------------+--------+-----------------------------+-------------+
      

                                       Table 4

  The following table maps terms between JOSE and COSE for PQC KEM algorithms.

        +==============+=======+====================+===============================+
        | Name                 | Value | Description                 | Recommended  |
        +==============+=======+====================+=============--------==========+
        | Kyber512             | TBD7  | Kyber512                    | No           |
        |                      |       |                             |              |
        +---------------------+--------+-----------------------------+--------------+
        | Kyber768             | TBD9  | Kyber768                    | No           |
        |                      |       |                             |              |
        +---------------------+--------+-----------------------------+--------------+

                                       Table 5

This example uses the following parameters:

* Algorithm for payload encryption: AES-GCM-128
* IV: 0x26, 0x68, 0x23, 0x06, 0xd4, 0xfb, 0x28, 0xca, 0x01, 0xb4, 0x3b, 0x80
* Algorithm for content key distribution: secp256r1_kyber512
* KID: "kid-4"

The COSE_Encrypt structure 

~~~

   96(
     [
       / protected h'a10101' / << {
           / alg / 1:1 / AES-GCM 128 /
         } >>,
       / unprotected / {
         / iv / 5:h'26682306D4FB28CA01B43B80'
       },
      / null because of detached ciphertext /
      null,
       / recipients / [
         [
           / protected h'Assuming -50 is assigned' / << {
               / alg / 1:-50 / secp256r1-ES_kyber512 /
             } >>,
           / unprotected / {
             / ephemeral / -1:{
               / kty / 1:1 /OKP/,
               / crv / -1:1 /secp256r1 or P-256/,
               / x / -2:h'415A8ED270C4B1F10B0A2D42B28EE6028CE25D74552CB4291A4069A2E989B0F6',
               / y / -3:h'CCC9AAF60514B9420C80619A4FF068BC1D77625BA8C90200882F7D5B73659E76'
             },
             / kid / 4:'kid-10'
           }
         ]
       ]
     ]
   )

~~~

                    Figure 1: COSE_Encrypt Example for secp256r1-ES_kyber512               
     

# Security Considerations

Security considerations from {{?RFC7748}} and {{?I-D.ounsworth-cfrg-kem-combiners}} apply here. The shared secrets computed in the hybrid key exchange should be computed in a way that achieves the "hybrid" property: the resulting secret is secure as long as at least one of the component key exchange algorithms is unbroken.

PQC KEMs used in the manner described in this document MUST explicitly be designed to be secure in the event that the public key is reused, such as achieving IND-CCA2 security. Kyber has such security properties.

# IANA Considerations

## JOSE

The following has to be added to the "JSON Web Key Parameters"
registry:

- Parameter Name: "kem"
- Parameter Description: PQC KEM Algorithm 
- Parameter Information Class: Public
- Used with "kty" Value(s): "OKP"
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)

- Parameter Name: "kem-pk"
- Parameter Description: PQC KEM Public Key 
- Parameter Information Class: Public
- Used with "kty" Value(s): "OKP"
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)

- Parameter Name: "kem-sk"
- Parameter Description: PQC KEM Private Key
- Parameter Information Class: Private
- Used with "kty" Value(s): "OKP"
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)

- Parameter Name: "kem-ct"
- Parameter Description: PQC KEM ciphertext
- Parameter Information Class: Public 
- Used with "kty" Value(s): "OKP"
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)

The following has to be added to the "JSON Web Signature and
Encryption Algorithms" registry:

- Algorithm Name: "x25519-ES_kyber768"
- Algorithm Description: Curve25519 elliptic curve + Kyber768 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp384r1-ES_kyber768"
- Algorithm Description: P-384 + Kyber768 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "x25519-ES_kyber512"
- Algorithm Description: Curve25519 elliptic curve + Kyber512 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp256r1-ES_kyber512"
- Algorithm Description: P-256 + Kyber512 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "x25519-ES_kyber768+A128KW"
- Algorithm Description: Curve25519 elliptic curve + Kyber768 parameter and CEK wrapped with "A128KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp384r1-ES_kyber768+A128KW"
- Algorithm Description: P-384 + Kyber768 parameter and CEK wrapped with "A128KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "x25519-ES_kyber512+A128KW"
- Algorithm Description: Curve25519 elliptic curve + Kyber512 parameter and CEK wrapped with "A128KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp256r1-ES_kyber512+A128KW"
- Algorithm Description: P-256 + Kyber512 parameter and CEK wrapped with "A128KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "x25519-ES_kyber768+A256KW"
- Algorithm Description: Curve25519 elliptic curve + Kyber768 parameter and CEK wrapped with "A256KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp384r1-ES_kyber768+A256KW"
- Algorithm Description: P-384 + Kyber768 parameter and CEK wrapped with "A256KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): S{{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "x25519-ES_kyber512+A256KW"
- Algorithm Description: Curve25519 elliptic curve + Kyber512 parameter and CEK wrapped with "A256KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp256r1-ES_kyber512+A256KW"
- Algorithm Description: P-256 + Kyber512 parameter and CEK wrapped with "A256KW" 
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{hybrid-kem}} of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

### JSON PQC KEM Registry {#JSON-KEM-REGISTRY}

   This section establishes the IANA "JSON PQC KEM"
   registry for JWK "kem" member values.  The registry records the PQC
   KEM name, implementation requirements, and a reference to the
   specification that defines it.  This specification registers the
   PQC KEM algorithms defined in {{kem}}.

   The implementation requirements of a PQC KEM may be changed over time
   as the cryptographic landscape evolves, for instance, to change the
   status of a PQC KEM to Deprecated or to change the status of a PQC KEM
   from Optional to Recommended+ or Required.  Changes of implementation
   requirements are only permitted on a Specification Required basis
   after review by the Designated Experts, with the new specification
   defining the revised implementation requirements level.

####  Registration Template

   PQC KEM name:
      The name requested (e.g., "Kyber512").  Because a core goal of this
      specification is for the resulting representations to be compact,
      it is RECOMMENDED that the name be short -- not to exceed 12
      characters without a compelling reason to do so.  This name is
      case sensitive.  Names may not match other registered names in a
      case-insensitive manner unless the Designated Experts state that
      there is a compelling reason to allow an exception.

   PQC KEM Description:
      Brief description of the PQC KEM (e.g., "Kyber512").

   JOSE Implementation Requirements:
      The PQC KEM implementation requirements for JWE, which must
      be one the words Required, Recommended, Optional, Deprecated, or
      Prohibited.  Optionally, the word can be followed by a "+" or "-".
      The use of "+" indicates that the requirement strength is likely
      to be increased in a future version of the specification.  The use
      of "-" indicates that the requirement strength is likely to be
      decreased in a future version of the specification.

   Change Controller:
      For Standards Track RFCs, list "IESG".  For others, give the name
      of the responsible party.  Other details (e.g., postal address,
      email address, home page URI) may also be included.

   Specification Document(s):
      Reference to the document or documents that specify the parameter,
      preferably including URIs that can be used to retrieve copies of
      the documents.  An indication of the relevant sections may also be
      included but is not required.

####  Initial Registry Contents

- PQC KEM name: "Kyber512"
- PQC KEM Description: Kyber512
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{kem}}

- PQC KEM name: "Kyber768"
- PQC KEM Description: Kyber768
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): {{kem}}

## COSE

The following has to be added to the "COSE Key Type Parameters"
registry:

- Key Type: OKP
- Name: kem
- Label : TBD2
- CBOR Type: int / tstr 
- Description: PQC KEM Algorithm
- Reference: This document (TBD)

- Key Type: OKP
- Name: kem-pk
- Label : TBD3
- CBOR Type: bstr
- Description: PQC KEM Public Key
- Reference: This document (TBD)

- Key Type: OKP
- Name: kem-sk
- Label : TBD4
- CBOR Type: bstr
- Description:  PQC KEM Private Key
- Reference: This document (TBD)

- Key Type: OKP
- Name: kem-ct
- Label : TBD5
- CBOR Type: bstr
- Description:  PQC KEM ciphertext 
- Reference: This document (TBD)

The following has to be added to the "COSE Algorithms" registry:

- Name: x25519-ES_kyber768
- Value: TBD10
- Description: Curve25519 elliptic curve + Kyber768 parameter
- Reference: This document (TBD)
- Recommended: No

- Name: secp384r1-ES_kyber768
- Value: TBD11
- Description: P-384 + Kyber768 parameter
- Reference: This document (TBD)
- Recommended: No

- Name: x25519-ES_kyber512
- Value: TBD12
- Description: Curve25519 elliptic curve + Kyber512 parameter
- Reference: This document (TBD)
- Recommended: No

- Name: secp256r1-ES_kyber512
- Value: TBD13
- Description: P-256 + Kyber512 parameter
- Reference: This document (TBD)
- Recommended: No

- Name: x25519-ES_kyber768+A128KW
- Value: TBD14
- Description: Curve25519 elliptic curve + Kyber768 parameter and CEK wrapped with "A128KW" 
- Reference: This document (TBD)
- Recommended: No

- Name: secp384r1-ES_kyber768+A128KW
- Value: TBD15
- Description: P-384 + Kyber768 parameter and CEK wrapped with "A128KW" 
- Reference: This document (TBD)
- Recommended: No

- Name: x25519-ES_kyber512+A128KW
- Value: TBD16
- Description: Curve25519 elliptic curve + Kyber512 parameter and CEK wrapped with "A128KW" 
- Reference: This document (TBD)
- Recommended: No

- Name: secp256r1-ES_kyber512+A128KW
- Value: TBD17
- Description: P-256 + Kyber512 parameter and CEK wrapped with "A128KW" 
- Reference: This document (TBD)
- Recommended: No

- Name: x25519-ES_kyber768+A256KW
- Value: TBD18
- Description: Curve25519 elliptic curve + Kyber768 parameter and CEK wrapped with "A256KW" 
- Reference: This document (TBD)
- Recommended: No

- Name: secp384r1-ES_kyber768+A256KW
- Value: TBD19
- Description: P-384 + Kyber768 parameter and CEK wrapped with "A256KW" 
- Reference: This document (TBD)
- Recommended: No

- Name: x25519-ES_kyber512+A256KW
- Value: TBD20
- Description: Curve25519 elliptic curve + Kyber512 parameter and CEK wrapped with "A256KW" 
- Reference: This document (TBD)
- Recommended: No

- Name: secp256r1-ES_kyber512+A256KW
- Value: TBD21
- Description: P-256 + Kyber512 parameter and CEK wrapped with "A256KW" 
- Reference: This document (TBD)
- Recommended: No

### COSE PQC KEM Registry

   This section establishes the IANA "COSE PQC KEM"
   registry for "kem" member values.  The registry records the PQC
   KEM name, implementation requirements, and a reference to the
   specification that defines it.  This specification registers the
   PQC KEM algorithms defined in {{cose-hybrid-kem}}.

   The implementation requirements of a PQC KEM may be changed over time
   as the cryptographic landscape evolves, for instance, to change the
   status of a PQC KEM to Deprecated or to change the status of a PQC KEM
   from Optional to Recommended+ or Required.  Changes of implementation
   requirements are only permitted on a Specification Required basis
   after review by the Designated Experts, with the new specification
   defining the revised implementation requirements level.

####  Registration Template

   Name:
      The name requested (e.g., "Kyber512").  Because a core goal of this
      specification is for the resulting representations to be compact,
      it is RECOMMENDED that the name be short -- not to exceed 12
      characters without a compelling reason to do so.  This name is
      case sensitive.  Names may not match other registered names in a
      case-insensitive manner unless the Designated Experts state that
      there is a compelling reason to allow an exception.
   
   Value: This is the value used for the label.  The label can be
      either an integer or a string.  Registration in the table is based
      on the value of the label requested.  Integer values between 1 and
      255 and strings of length 1 are designated as "Standards Action".
      Integer values from 256 to 65535 and strings of length 2 are
      designated as "Specification Required".  Integer values of greater
      than 65535 and strings of length greater than 2 are designated as
      "Expert Review".  Integer values in the range -1 to -65536 are
      "delegated to the COSE Header Algorithm Parameters registry".
      Integer values less than -65536 are marked as private use.

   Description:
      Brief description of the PQC KEM (e.g., "Kyber512").

   Change Controller:
      For Standards Track RFCs, list "IESG".  For others, give the name
      of the responsible party.  Other details (e.g., postal address,
      email address, home page URI) may also be included.

   Reference:
      Reference to the document or documents that specify the parameter,
      preferably including URIs that can be used to retrieve copies of
      the documents.  An indication of the relevant sections may also be
      included but is not required.
   
    Recommended:  Does the IETF have a consensus recommendation to use
      the algorithm?  The legal values are 'Yes', 'No', and
      'Deprecated'.

####  Initial Registry Contents

- Name: "Kyber512"
- Value: TBD7
- Description: Kyber512
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

- Name: "Kyber768"
- Value: TBD9
- Description: Kyber768
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: No

# Acknowledgments
{: numbered="false"}

Thanks to Mike Ounsworth for the discussion and comments.