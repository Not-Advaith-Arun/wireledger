# Wireledger

**Portable, signed histories of what a TLS endpoint presented.**

Record certificate observations, sign and chain their history, retain independent checkpoints, and verify or compare the evidence offline. Distinguish certificate renewals from public-key changes without treating either as an automatic attack verdict.

## Try it

Python 3.11+ and `cryptography>=44,<50`.

```sh
git clone https://github.com/Not-Advaith-Arun/wireledger.git
cd wireledger
python3 -m venv .venv
. .venv/bin/activate
python3 -m pip install -e .
python3 -m wireledger showcase -o /tmp/wireledger-showcase.html
python3 -m wireledger demo
```

Open `/tmp/wireledger-showcase.html` for an offline visual walkthrough. The demo starts a disposable **loopback-only** TLS service, observes renewal/key rotation, detects modified history and checkpoint-anchored truncation, and independently audits captured certificate evidence. It uses temporary lab identities, not account credentials.

## Observe an endpoint

```sh
python3 -m wireledger init witness
python3 -m wireledger observe witness example.com --vantage home
python3 -m wireledger checkpoint witness checkpoint.json
python3 -m wireledger verify witness/observations.jsonl \
  --public-key witness/witness.pub --checkpoint checkpoint.json
```

`observe` makes a network connection to the endpoint you name. Other review workflows operate on supplied files. TLS verification remains enabled. Keep private signing keys private, distribute public keys through a trusted channel, and retain checkpoints independently of the ledger.

## Scope

A working research prototype, **not an audited security product or Certificate Transparency implementation**. Signatures establish consistency relative to a trusted key; they do not establish truthful vantage labels, trusted timestamps, an actual handshake, or absence of compromise. Truncation detection requires an independently retained checkpoint. An offline certificate-path audit has its own explicit trust and time policy.

## Validation

```sh
python3 -m unittest discover -s tests -v
```

Includes loopback end-to-end cases, tampering/truncation checks, explicit policy boundaries, and browser showcase checks.
