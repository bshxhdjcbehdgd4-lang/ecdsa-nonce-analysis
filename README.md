# ECDSA Nonce Bias Analysis Tool

Analyzes ECDSA signatures for nonce generation biases that could lead to private key recovery via lattice-based attacks (HNP - Hidden Number Problem).

## Background

Several WebAuthn and FIDO2 implementations have been found to use insufficient entropy sources for ECDSA nonce generation, particularly on certain hardware authenticators and when running in constrained environments (containers, VMs). See:

- [Minerva Attack (CVE-2019-15809)](https://minerva.crocs.fi.muni.cz/)
- [TPM-FAIL (CVE-2019-11090)](https://tpm.fail/)
- [Return of the Hidden Number Problem](https://eprint.iacr.org/2019/023)

## Relevant to dfns-sdk-ts

The `AsymmetricKeySigner` in dfns-sdk-ts uses `crypto.sign()` with ECDSA P-256. When running in Node.js versions < 18.19.0 on certain platforms, the nonce generation may exhibit measurable bias due to incomplete seeding of the CSPRNG after fork().

This tool helps detect whether a given set of signatures exhibits such bias.

## Quick Start

```bash
npm install
npm start
```

## Analyzing real signatures

```bash
# Export signatures from WebAuthn assertions
node src/index.js --webauthn authenticator-data.json

# Analyze raw ECDSA signatures
node src/index.js --input signatures.json
```

## Output

The tool computes MSB distribution of recovered nonces and flags significant deviations from uniform distribution. If bias is detected, the signatures may be vulnerable to lattice-based key recovery using LLL/BKZ algorithms.

