---
title: "Hybrid key exchange in JOSE and CBOR"
abbrev: "Hybrid key exchange in JOSE and CBOR"
category: std

docname: draft-ra-jose-hybrid-encrypt
submissiontype: IETF
number:
date:
consensus: true
v: 3
area: "Security"
workgroup: "JOSE"
keyword:
 - PQC
 - JOSE
 

venue:
  group: "jose"
  type: "Working Group"
  mail: "jose@ietf.org"
  arch: "https://mailarchive.ietf.org/arch/browse/jose/"
  

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
  PQCAPI:
     title: "PQC - API notes"
     target: https://csrc.nist.gov/CSRC/media/Projects/Post-Quantum-Cryptography/documents/example-files/api-notes.pdf
     date: false

     
--- abstract

Hybrid key exchange refers to using multiple key exchange algorithms simultaneously and combining the result with the goal of providing
security even if all but one of the component algorithms is broken. It is motivated by transition to post-quantum cryptography. 
This document provides a construction for hybrid key exchange in JOSE. It defines the use of traditional and PQC algorithms, 
a hybrid post-quantum KEM, for JOSE. 



--- middle

# Introduction

This document gives a construction for hybrid key exchange in JOSE. The overall design approach is a simple, "concatenation"-based approach to use a “hybrid” shared secret.

# Conventions and Definitions

{::boilerplate bcp14-tagged}
This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional" algorithms:  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms or elliptic curve discrete logarithms. In the context of JOSE, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman Ephemeral Static {{?RFC6090}} {{?RFC8037}}. 

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

Building a PQ/T hybrid KEM requires a secure function which combines the output of both component KEMs to form a single output.  Several IETF protocols are adding PQ/T hybrid KEM mechanisms as part of their overall post-quantum migration strategies, examples include TLS 1.3 {{?I-D.ietf-ietf-tls-hybrid-design}}, IKEv2 {{?RFC9370}}.

The migration to PQ/T Hybrid KEM calls for performing multiple key encapsulations in parallel and then combining their outputs to derive a single shared secret. It is compatible with NIST SP 800-56Cr2 [SP800-56C] when viewed as a key derivation function. The hybrid scheme defined in this document is the combination of Traditional and Post-Quantum Algorithms. The Key agreement Traditional and Post-Quantum Algorithms are used in parallel to generate shared secrets. The two shared secrets are concatenated togethor and used as the shared secret in JOSE. 

The JSON Web Algorithms (JWA) {{?RFC5652}} in Section 4.6 defines two ways using the key agreement result. When Direct Key Agreement is employed, the shared secret will be the content encryption key (CEK). When Key Agreement with Key Wrapping is employed, the shared secret will wrap the CEK. 

# KEM Combiner

The specification uses the KEM combiner function defined in {{?I-D.ounsworth-cfrg-kem-combiners}} that takes in two or more shared secrets and returns a combined shared secret. In case of PQ/T Hybrid KEM, the shared secrets are the output of the traditional and PQC KEMs. The fixedInfo string helps prevent cross-context attacks by making this key derivation unique to its protocol context. The KEM combiner is defined in Section 3 of {{?I-D.ounsworth-cfrg-kem-combiners}}. The KDF and Hash functions will be SHA3-256 (Hash Size = 256 bit) and the counter will be initialized with a value of 1. The fixedInfo string carrying the protocol-specific KDF binding will be set to "Javascript Object Signing and Encryption". 

# KEM PQC Algorithms

The National Institute of Standards and Technology (NIST) started a process to solicit, evaluate, and standardize one or more quantum-resistant public-key cryptographic algorithms, as seen [here](https://csrc.nist.gov/projects/post-quantum-cryptography). Said process has reached its [first announcement](https://csrc.nist.gov/publications/detail/nistir/8413/final) in July 5, 2022, which stated which candidates to be standardized for KEM:

* Key Encapsulation Mechanisms (KEMs): [CRYSTALS-Kyber](https://pq-crystals.org/kyber/): Kyber is a module learning with errors (MLWE)-based key encapsulation mechanism.

NIST announced as well that they will be [opening a fourth round](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/guidelines-for-submitting-tweaks-fourth-round.pdf) to standardize an alternative KEM, and a [call](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/call-for-proposals-dig-sig-sept-2022.pdf) for new candidates for a post-quantum signature algorithm.

## Kyber

Kyber offers several parameter sets with varying levels of security and performance trade-offs. This document specifies the use of the Kyber algorithm at three security levels: Kyber512, Kyber768 and
Kyber1024. Kyber key generation, encapsulation and decaspulation functions are defined in {{?I-D.cfrg-schwabe-kyber}}.

# Hybrid Key Representation with JOSE

A new key type (kty) value "HYBRID" is defined for expressing the cryptographic keys for PQ/T Hybrid KEM in JSON Web Key (JWK) form, the following rules apply:

* The parameter "kty" MUST be present and set to "HYBRID".
* The parameter "alg" MUST be specified, and its value MUST be one of the values specified in the table below:
  
              +======================+===================================+
              | alg                  | Description                       |
              +========+=================================================+
              | x25519_kyber512      | Curve25519 elliptic curve +       |
              |                      | Kyber512 paraneter                |
              +========+=================================================+
              | secp384r1_kyber512   | P-384 + Kyber512 paraneter        |
              |                      |                                   |
              +========+=================================================+
              | x25519_kyber768      | Curve25519 elliptic curve +       |
              |                      | Kyber768 paraneter                |
              +========+=================================================+
              | secp256r1_kyber768   | P-256 +  Kyber512 paraneter       |
              |                      |                                   |
              +==========================================================+

                                 Table 1
                      

* The parameter "x" MUST be present and contain the concatenatnated traditional and PQC public key encoded using the base64url {{?RFC4648}} encoding.
* The parameter "d" MUST be present for private keys and contains the concatenated traditional and PQC private key encoded using the base64url encoding. This parameter MUST NOT be present for public keys.

# Hybrid Key Representation with COSE

The approach taken here matches the work done to support secp256k1 in JOSE and COSE in {{?RFC8812}}. The following tables map terms between JOSE and COSE for PQ/T Hybrid KEM.

        +==============+=======+====================+===============================+
        | Name                 | Value | Description                 | Recommended  |
        +==============+=======+====================+=============--------==========+
        | x25519_kyber512      | TBD   | Curve25519 elliptic curve + | No           |
        |                      |       | Kyber512 paraneter          |              |
        +--------------+-------+--------------------+-------------------------=-----+
        | secp384r1_kyber512   | TBD   | P-384 + Kyber512 paraneter  | No           |
        |                      |       |                             |              |
        +--------------+-------+--------------------+-------------------------=-----+
        | x25519_kyber768      | TBD   | Curve25519 elliptic curve   | No           |
        |                      |       | Kyber768 paraneter          |              |
        +--------------+-------+--------------------+-------------------------=-----+
        | secp256r1_kyber768   | TBD   | P-256 + Kyber512 paraneter  | No           |
        |                      |       |                             |              |
        +--------------+-------+--------------------+-------------------------=-----+

                                       Table 2

   The following tables map terms between JOSE and COSE for key types.

        +==============+=======+====================+===============================+
        | Name                 | Value | Description                 | Recommended  |
        +==============+=======+====================+=============--------==========+
        | HYBRID               | TBD   | kty for PQ/T Hybrid KEM     | No           |
        |                      |       | Kyber512 paraneter          |              |
        +--------------+-------+--------------------+-------------------------=-----+

                                       Table 3

# Security Considerations

Security considerations from {{?RFC7748}} and {{?I-D.ounsworth-cfrg-kem-combiners}} apply here. The nominal security strengths of X25519 and X448 are ~126 and ~223 bits.  Therefore, using 256-bit symmetric encryption (especially key wrapping and encryption) with X448 is RECOMMENDED.

# IANA Considerations

## JOSE

The following has NOT YET been added to the "JSON Web Key Types"
registry:

- Name: "HYBRID"
- Description: Hybrid Key Exchange
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)

The following has NOT YET been added to the "JSON Web Key Parameters"
registry:

- Parameter Name: "d"
- Parameter Description: The private key
- Parameter Information Class: Private
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

The following has NOT YET been added to the "JSON Web Key Parameters"
registry:

- Parameter Name: "x"
- Parameter Description: The public key
- Parameter Information Class: Public
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

The following has NOT YET been added to the "JSON Web Signature and
Encryption Algorithms" registry:

- Algorithm Name: "x25519_kyber768"
- Algorithm Description: Curve25519 elliptic curve + Kyber768 paraneter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis Documents(s): (TBD)

The following has NOT YET been added to the "JSON Web Signature and
Encryption Algorithms" registry:

- Algorithm Name: "secp384r1_kyber768"
- Algorithm Description: P-384 + Kyber768 paraneter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis 

The following has NOT YET been added to the "JSON Web Signature and
Encryption Algorithms" registry:

- Algorithm Name: "x25519_kyber512"
- Algorithm Description: Curve25519 elliptic curve + Kyber512 paraneter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis 

The following has NOT YET been added to the "JSON Web Signature and
Encryption Algorithms" registry:

- Algorithm Name: "secp256r1_kyber512"
- Algorithm Description: P-256 + Kyber768 paraneter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis 

## COSE

TODO

# Acknowledgments
{: numbered="false"}