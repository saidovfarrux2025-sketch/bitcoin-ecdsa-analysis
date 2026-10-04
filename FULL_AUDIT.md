# Full Bitcoin ECDSA Audit

This document describes a defensive, audit-oriented Bitcoin ECDSA review workflow. It covers transaction collection, signature parsing, repeated-nonce heuristics, malformed signing patterns, wallet and signer risk review, and structured reporting.

## 1. Objective

The purpose is to review Bitcoin ECDSA signature use patterns and detect suspicious conditions such as:
- repeated nonce / repeated `R` values
- malformed DER signatures
- low-S or high-S normalization issues
- suspicious transaction clustering
- wallet implementation or entropy weakness indicators

This is a defensive analysis workflow. It does not include private-key recovery logic or exploitation code.

## 2. Data sources

- public Bitcoin APIs such as Blockstream or Mempool
- address-to-tx lookup
- tx detail lookup
- scriptSig and witness inspection
- optional internal wallet or signer metadata if available

## 3. Collection workflow

1. Define target addresses or transaction set
2. Fetch recent tx history for each address
3. Retrieve tx details for each tx
4. Iterate through `vin` inputs
5. Extract `scriptSig`, `witness`, `prevout`, and address metadata
6. Save raw data for reproducible audit records

## 4. Signature parsing

For each input, inspect `scriptSig` and witness for DER-encoded ECDSA signatures.

Typical DER structure:
- `0x30` sequence tag
- length field
- `0x02` integer tag for `r`
- `0x02` integer tag for `s`

The parser should do the following:
- check DER tag and length
- extract `r` and `s`
- compute `der_length`
- flag malformed or non-canonical encodings
- mark `low_s` / `high_s` if applicable

## 5. Nonce-related detection

### 5.1 Repeated `R` values
This is the strongest public signal of nonce reuse.

If two or more signatures share the same `R`, then the signer likely reused the same nonce `k` in different ECDSA equations.

This is a significant risk indicator, even though it does not by itself recover a private key in a live audit script.

### 5.2 Time-window grouping
Look for repeated `R` values across multiple transactions in a narrow time interval.

Patterns to review:
- same address
- same wallet family
- multiple addresses from one wallet
- repeated signing bursts within the same block window

### 5.3 Deterministic nonce review
Review if the signer uses:
- RFC6979 deterministic nonce generation
- custom PRNG
- static or repeated nonce sources
- per-message or per-key derivation that may be predictable

### 5.4 Entropy review
Check if the signer has:
- strong CSPRNG usage
- poor entropy seeding
- PRNG state reuse
- weak randomness in embedded systems or legacy wallet code

### 5.5 Side-channel risk review
Check whether the signing implementation is exposed to:
- timing leakage
- cache leakage
- power analysis
- fault injection
- poor constant-time behavior

## 6. Signature anomaly checks

Check for:
- missing `scriptSig`
- missing witness
- empty signature data
- invalid DER length
- malformed sequence tags
- noncanonical `s` encoding
- suspiciously long signature payloads
- repeated signature shapes across many inputs

## 7. Transaction anomaly checks

Review transaction level patterns such as:
- same address repeated across many txs
- suspiciously tight clustering of txs in time
- repeated spend behaviors from one wallet
- abnormal change address patterns
- unusual multisig or SegWit patterns

## 8. Output structure

Each observation can include:
- address
- txid
- vin index
- tx type
- scriptSig / witness
- r_hex
- s_hex
- der_length
- low_s
- repeated_r
- malformed_der
- risk_score
- warnings

## 9. Risk scoring example

Suggested risk model:
- repeated R: +30
- malformed DER: +20
- no valid signature: +10
- unusually long DER: +10
- high-S / low-S warning: +5
- same-wallet cluster: +15
- deterministic nonce concern: +20
- entropy concern: +15

Risk bands:
- 0-20: low risk
- 21-50: moderate risk
- 51-100: high risk
- >100: severe review needed

## 10. Reporting output

Produce:
- per-address summary
- per-signature observations
- aggregated risk report
- JSON export
- CSV export

## 11. Example JSON schema

```json
{
  "address": "bc1qexample",
  "txid": "abc123",
  "vin_index": 0,
  "script_sig": "3045022100...",
  "r_hex": "abcd",
  "s_hex": "ef01",
  "der_length": 70,
  "repeated_r": true,
  "malformed_der": false,
  "low_s": false,
  "risk_score": 35,
  "warnings": [
    "Repeated R value across multiple signatures",
    "Possible nonce reuse heuristic"
  ]
}
```

## 12. Safety note

This workflow is limited to:
- pattern analysis
- risk scoring
- signature structure review
- transaction chain investigation
- wallet signing audit

It does not include:
- private key recovery steps
- attack execution
- exploit generation
- secret extraction logic

## 13. Recommended audit checklist

- Target addresses defined
- Recent txs collected
- All inputs inspected
- DER signature parsing completed
- R/S values extracted
- Repeated R clusters found or ruled out
- DER validity checked
- Witness / scriptSig checked
- Time-window pattern analysis completed
- Entropy and deterministic nonce review done
- Side-channel review performed
- Risk score assigned
- JSON/CSV report exported

## 14. Summary

A full audit should answer the following questions:
- Were signatures malformed or noncanonical?
- Did a signer reuse the same nonce (`R` repeated)?
- Was the signing logic deterministic or weakly entropy-backed?
- Are there wallet-level patterns suggesting poor nonce generation?
- Are there transaction clusters or signature anomalies that deserve escalation?

This is a complete defensive Bitcoin ECDSA review framework.
