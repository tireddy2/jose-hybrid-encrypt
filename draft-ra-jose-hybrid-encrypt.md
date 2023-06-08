---
title: "Hybrid key exchange in JOSE and COSE"
abbrev: "Hybrid key exchange in JOSE and COSE"
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
 - Hybrid
 - COSE
 

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
This document provides a construction for hybrid key exchange in JOSE and COSE. It defines the use of traditional and PQC algorithms, 
a hybrid post-quantum KEM, for JOSE and COSE. 


--- middle

# Introduction

The migration to PQC is unique in the history of modern digital cryptography in that neither the traditional algorithms nor the post-quantum algorithms are fully trusted to protect data for the required data lifetimes. The traditional algorithms, such as RSA and elliptic curve, will fall to quantum cryptalanysis, while the post-quantum algorithms face uncertainty about the underlying mathematics, compliance issues, unknown vulnerabilities, hardware and software implementations that have not had sufficient maturing time to rule out classical cryptanalytic attacks and implementation bugs.

During the transition from traditional to post-quantum algorithms, there is a desire or a requirement for protocols that use both algorithm types. {{?I-D.ietf-pquip-pqt-hybrid-terminology}} defines terminology for the Post-Quantum and Traditional Hybrid Schemes.

This document gives a construction for hybrid key exchange in Javascript Object Signing and Encryption (JOSE) and CBOR Object Signing and Encryption (COSE). The overall design approach is a simple, "concatenation"-based approach to use a “hybrid” shared secret.

# Conventions and Definitions

{::boilerplate bcp14-tagged}
This document makes use of the terms defined in {{?I-D.ietf-pquip-pqt-hybrid-terminology}}. For the purposes of this document, it is helpful to be able to divide cryptographic algorithms into two classes:

"Traditional" algorithms:  An asymmetric cryptographic algorithm based on integer factorisation, finite field discrete logarithms or elliptic curve discrete logarithms. In the context of JOSE, examples of traditional key exchange algorithms include Elliptic Curve Diffie-Hellman Ephemeral Static {{?RFC6090}} {{?RFC8037}}. In the context of COSE, examples of traditional key exchange algorithms include Ephemeral-Static (ES) DH and Static-Static (SS) DH {{?RFC9052}}. 

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

The migration to PQ/T Hybrid KEM calls for performing multiple key encapsulations in parallel and then combining their outputs to derive a single shared secret. It is compatible with NIST SP 800-56Cr2 [SP800-56C] when viewed as a key derivation function. The hybrid scheme defined in this document is the combination of Traditional and Post-Quantum Algorithms. The Key agreement Traditional and Post-Quantum Algorithms are used in parallel to generate shared secrets. The two shared secrets are concatenated togethor and used as the shared secret in JOSE and COSE. 

The JSON Web Algorithms (JWA) {{?RFC5652}} in Section 4.6 defines two ways using the key agreement result. When Direct Key Agreement is employed, the shared secret will be the content encryption key (CEK). When Key Agreement with Key Wrapping is employed, the shared secret will wrap the CEK. Simiarly, COSE in Sections 8.5.4 and 8.5.5 {{?RFC5652}} define the Direct Key Agreement and Key Agreement with Key Wrap classes.

# KEM Combiner {#kem-combiner}

The specification uses the KEM combiner defined in {{?I-D.ounsworth-cfrg-kem-combiners}} that takes in two or more shared secrets and returns a combined shared secret. In case of PQ/T Hybrid KEM, the shared secrets are the output of the traditional and PQC KEMs. The fixedInfo string defined in Section 3.2 of {{?I-D.ounsworth-cfrg-kem-combiners}} helps prevent cross-context attacks by making this key derivation unique to its protocol context. The KEM combiner function is defined in Section 3 of {{?I-D.ounsworth-cfrg-kem-combiners}}. 

In case of JOSE and COSE, the KDF and Hash functions will be SHA3-256 (Hash Size = 256 bit) and the counter will be initialized with a value of 0x00000001 (Section 4 of {{?I-D.ounsworth-cfrg-kem-combiners}}). In case of JOSE, the fixedInfo string carrying the protocol-specific KDF binding will be set to "Javascript Object Signing and Encryption". In case of COSE, the fixedInfo string carrying the protocol-specific KDF binding will be set to "CBOR Object Signing and Encryption". 

# KEM PQC Algorithms

The National Institute of Standards and Technology (NIST) started a process to solicit, evaluate, and standardize one or more quantum-resistant public-key cryptographic algorithms, as seen [here](https://csrc.nist.gov/projects/post-quantum-cryptography). Said process has reached its [first announcement](https://csrc.nist.gov/publications/detail/nistir/8413/final) in July 5, 2022, which stated which candidates to be standardized for KEM:

* Key Encapsulation Mechanisms (KEMs): [CRYSTALS-Kyber](https://pq-crystals.org/kyber/): Kyber is a module learning with errors (MLWE)-based key encapsulation mechanism.

NIST announced as well that they will be [opening a fourth round](https://csrc.nist.gov/csrc/media/Projects/post-quantum-cryptography/documents/round-4/guidelines-for-submitting-tweaks-fourth-round.pdf) to standardize an alternative KEM, and a [call](https://csrc.nist.gov/csrc/media/Projects/pqc-dig-sig/documents/call-for-proposals-dig-sig-sept-2022.pdf) for new candidates for a post-quantum signature algorithm.

## Kyber

Kyber offers several parameter sets with varying levels of security and performance trade-offs. This document specifies the use of the Kyber algorithm at two security levels: Kyber512 and Kyber768
Kyber key generation, encapsulation and decaspulation functions are defined in {{?I-D.cfrg-schwabe-kyber}}.

# Hybrid Key Representation with JOSE {#hybrid-kem}

A new key type (kty) value "HYBRID" is defined for expressing the cryptographic keys for PQ/T Hybrid KEM in JSON Web Key (JWK) form, the following rules apply:

* The parameter "kty" MUST be present and set to "HYBRID".
* The parameter "alg" MUST be specified, and its value MUST be one of the values specified in the table below:
  
              +======================+===================================+
              | alg                  | Description                       |
              +========+=================================================+
              | x25519_kyber512      | Curve25519 elliptic curve +       |
              |                      | Kyber512 parameter                |
              +========+=================================================+
              | secp384r1_kyber768   | P-384 + Kyber768 parameter        |
              |                      |                                   |
              +========+=================================================+
              | x25519_kyber768      | Curve25519 elliptic curve +       |
              |                      | Kyber768 parameter                |
              +========+=================================================+
              | secp256r1_kyber512   | P-256 +  Kyber512 parameter       |
              |                      |                                   |
              +==========================================================+

                                 Table 1
                      
* The parameter "pq-kem" MUST be present and set to the PQC KEM algorithm.
* The parameter "pq-pk" MUST be present and contains the PQC KEM public key encoded using the base64url {{?RFC4648}} encoding.
* The parameter "pq-sk" MUST be present for private keys and contains the PQC KEM private key encoded using the base64url encoding. This parameter MUST NOT be present for public keys.
* The parameter "crv" MUST be present and contains the Elliptic Curve Algorithm used (from the "JSON Web Elliptic Curve" registry).
* The parameter "x" MUST be present and contains the x coordinate for the Elliptic Curve point encoded using the base64url {{?RFC4648}} encoding.
* The parameter "y" MUST be present and contains the y coordinate for the Elliptic Curve point encoded using the base64url {{?RFC4648}} encoding. This parameter is not present for "X25519".
* The parameter "d" MUST be present for private keys and contains the Elliptic Curve Algorithm private key encoded using the base64url encoding. This parameter MUST NOT be present for public keys.

## HYBRID {#hybrid}

   The following key subtypes are defined here for purpose of "PQ/T Hybrid KEM in JSON Web Key (JWK) form" (HYBRID):

      "pq-kem"          PQC KEM Applied
      Kyber512            Kyber512          
      Kyber768            Kyber768

## Example Hybrid Key Agreement Computation

   This example uses Hybrid Key Agreement and the KEM Combiner to derive
   the CEK in the manner described in {{kem-combiner}}.  In this example, the
   Hybrid Direct Key Agreement mode ("alg" value "HYBRID") is used to
   produce an agreed-upon key for AES GCM with a 128-bit key ("enc"
   value "A128GCM").

   In this example, a producer Alice is encrypting content to a consumer
   Bob.  The producer (Alice) generates an ephemeral key for the key
   agreement computation.  Alice's ephemeral key (in JWK format) used
   for the key agreement computation in this example (including the
   private part) is:

     {"kty":"EC",
      "crv":"P-256",    
      "x":"alice_eph_public_key_x",
      "y":"alice_eph_public_key_y",
      "d":"alice_eph_private_key"
     }

   The consumer's (Bob's) key (in JWK format) used for the key agreement
   computation in this example (including the private part) is:

     {"kty":"HYBRID",
      "pq-kem": "kyber512",
      "pq-pk":"bob_kyber_public_key",
      "pq-sk":"bob_kyber_private_key"
      "crv":"P-256",
      "x":"bob_public_key_x",
      "y":"bob_public_key_y",
      "d":"bob_private_key"
     }

   Header Parameter values used in this example are as follows.

     {"alg":"secp256r1_kyber512",
      "enc":"A128GCM",
      "apu":"QWxpY2U",  // base64url encoding of the UTF-8 string "Alice"
      "apv":"Qm9i",    // base64url encoding of the UTF-8 string "Bob"
      "epk":
       {"kty":"EC",
        "crv":"P-256",
        "x":"alice_eph_public_key_x",
        "y":"alice_eph_public_key_y",
       }
     }
   

# Hybrid Key Representation with COSE

The approach taken here matches the work done to support PQ/T Hybrid KEM in JOSE and COSE in {{?RFC8812}}. The following tables map terms between JOSE and COSE for PQ/T Hybrid KEM.

        +==============+=======+====================+===============================+
        | Name                 | Value | Description                 | Recommended  |
        +==============+=======+====================+=============--------==========+
        | x25519_kyber512      | TBD12 | Curve25519 elliptic curve + | TBD40        |
        |                      |       | Kyber512 parameter          |              |
        +--------------+-------+--------------------+-------------------------=-----+
        | secp384r1_kyber768   | TBD11 | P-384 + Kyber768 parameter  | TBD41        |
        |                      |       |                             |              |
        +--------------+-------+--------------------+-------------------------=-----+
        | x25519_kyber768      | TBD10 | Curve25519 elliptic curve   | TBD42        |
        |                      |       | Kyber768 parameter          |              |
        +--------------+-------+--------------------+-------------------------=-----+
        | secp256r1_kyber512   | TBD13 | P-256 + Kyber512 parameter  | TBD43        |
        |                      |       |                             |              |
        +--------------+-------+--------------------+-------------------------=-----+

                                       Table 2

   The following tables map terms between JOSE and COSE for key types.

        +==============+=======+====================+===============================+
        | Name                 | Value | Description                 | Recommended  |
        +==============+=======+====================+=============--------==========+
        | HYBRID               | TBD   | kty for PQ/T Hybrid KEM     | TBD44        |
        |                      |       | Kyber512 parameter          |              |
        +--------------+-------+--------------------+-------------------------=-----+

                                       Table 3

# Security Considerations

Security considerations from {{?RFC7748}} and {{?I-D.ounsworth-cfrg-kem-combiners}} apply here. 

# IANA Considerations

## JOSE

The following has to be been added to the "JSON Web Key Types"
registry:

- Name: "HYBRID"
- Description: Hybrid Key Exchange
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)

The following has to be added to the "JSON Web Key Parameters"
registry:

- Parameter Name: "crv"
- Parameter Description: The EC used
- Parameter Information Class: Public
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

- Parameter Name: "d"
- Parameter Description: The private key
- Parameter Information Class: Private
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

- Parameter Name: "x"
- Parameter Description: x coordinate for the public key
- Parameter Information Class: Public
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

- Parameter Name: "y"
- Parameter Description: y coordinate for the public key
- Parameter Information Class: Public
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

- Parameter Name: "pq-kem"
- Parameter Description: PQC KEM Algorithm 
- Parameter Information Class: Public
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

- Parameter Name: "pq-pk"
- Parameter Description: PQC KEM Public Key 
- Parameter Information Class: Public
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

- Parameter Name: "pq-sk"
- Parameter Description: PQC KEM Private Key
- Parameter Information Class: Private
- Used with "kty" Value(s): "HYBRID"
- Change Controller: IESG
- Specification Document(s): Section 2 of RFC 8037

The following has to be added to the "JSON Web Signature and
Encryption Algorithms" registry:

- Algorithm Name: "x25519_kyber768"
- Algorithm Description: Curve25519 elliptic curve + Kyber768 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp384r1_kyber768"
- Algorithm Description: P-384 + Kyber768 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "x25519_kyber512"
- Algorithm Description: Curve25519 elliptic curve + Kyber512 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

- Algorithm Name: "secp256r1_kyber512"
- Algorithm Description: P-256 + Kyber512 parameter
- Algorithm Usage Location(s): "alg"
- JOSE Implementation Requirements: Optional
- Change Controller: IESG
- Specification Document(s): Section 6 of this document (TBD)
- Algorithm Analysis Documents(s): (TBD20)

### JSON PQC KEM Registry

   This section establishes the IANA "JSON PQC KEM"
   registry for JWK "pq-kem" member values.  The registry records the PQC
   KEM name, implementation requirements, and a reference to the
   specification that defines it.  This specification registers the
   PQC KEM algorithms defined in {{hybrid-kem}}.

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
- JOSE Implementation Requirements: Required
- Change Controller: IESG
- Specification Document(s): {{hybrid}}

- PQC KEM name: "Kyber768"
- PQC KEM Description: Kyber768
- JOSE Implementation Requirements: Required
- Change Controller: IESG
- Specification Document(s): {{hybrid}}

## COSE

The following has to be been added to the "COSE Key Types"
registry:

- Name: "HYBRID"
- Value: TBD1
- Description: Hybrid Key Exchange
- Reference: This document (TBD)

The following has to be added to the "COSE Key Type Parameters"
registry:

- Key Type: TBD1
- Name: crv
- Label : -1
- CBOR Type: int / tstr 
- Description: The EC used
- Reference: This document (TBD)

- Key Type: TBD1
- Name: d
- Label : -4
- CBOR Type: bstr
- Description: The Private key
- Reference: This document (TBD)

- Key Type: TBD1
- Name: x
- Label : -2
- CBOR Type: bstr
- Description: x coordinate for the public key
- Reference: This document (TBD)

- Key Type: TBD1
- Name: y
- Label : -3
- CBOR Type: bstr / bool 
- Description:  y coordinate for the public key
- Reference: This document (TBD)

- Key Type: TBD1
- Name: pq-kem
- Label : TBD2
- CBOR Type: int / tstr 
- Description: PQC KEM Algorithm
- Reference: This document (TBD)

- Key Type: TBD1
- Name: pq-pk
- Label : TBD3
- CBOR Type: bstr
- Description: PQC KEM Public Key
- Reference: This document (TBD)

- Key Type: TBD1
- Name: pq-sk
- Label : TBD4
- CBOR Type: bstr
- Description:  PQC KEM Private Key
- Reference: This document (TBD)

The following has to be added to the "COSE Algorithms" registry:

- Name: x25519_kyber768
- Value: TBD10
- Description: Curve25519 elliptic curve + Kyber768 parameter
- Reference: This document (TBD)
- Recommended: TBD7

- Name: secp384r1_kyber768
- Value: TBD11
- Description: P-384 + Kyber768 parameter
- Reference: This document (TBD)
- Recommended: TBD7

- Name: x25519_kyber512
- Value: TBD12
- Description: Curve25519 elliptic curve + Kyber512 parameter
- Reference: This document (TBD)
- Recommended: TBD7

- Name: secp256r1_kyber512
- Value: TBD13
- Description: Curve25519 elliptic curve + Kyber512 parameter
- Reference: This document (TBD)
- Recommended: TBD7

### COSE PQC KEM Registry

   This section establishes the IANA "COSE PQC KEM"
   registry for "pq-kem" member values.  The registry records the PQC
   KEM name, implementation requirements, and a reference to the
   specification that defines it.  This specification registers the
   PQC KEM algorithms defined in {{hybrid-kem}}.

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
- Recommended: TBD50

- Name: "Kyber768"
- Value: TBD9
- Description: Kyber768
- Change Controller: IESG
- Reference: This document (TBD)
- Recommended: TBD51

# Acknowledgments
{: numbered="false"}