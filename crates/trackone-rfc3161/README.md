# trackone-rfc3161

Verification of the strict VTL RFC 3161 archived timestamp profile using RFC
5816 `SigningCertificateV2`, SHA-256 signer-certificate pinning, and historical
CRL-based certificate-path evaluation.

The token is signer-identifiable because the VTL profile requires
`certReq=TRUE` and an embedded leaf certificate. It is not self-contained:
trust anchors, optional intermediates, complete base CRLs, algorithm policy,
and the signer pin remain deployment-managed.

The verification pipeline bounds the response and external-process runtime,
extracts an explicitly untrusted candidate `genTime`, runs `openssl ts
-verify`, then runs `openssl verify` on the exact CMS-selected signer using
`-purpose timestampsign`, `-attime`, `-CRLfile`, and `-crl_check_all`. Rust
parsing finally enforces the strict VTL representation and RFC 5816 binding.

Historical path evaluation uses the signed TSA-asserted `genTime`. It does not
prove first observation, prevent every post-compromise backdating attack, or
constitute comprehensive long-term validation. Only complete base CRLs are
supported; delta CRLs, indirect CRLs, and network retrieval are rejected.
