# XELIS-HE

All rights reserved.

This project is a simple Proof-of-Concept (PoC) implementation to provide confidential transactions using Homomorphic Encryption and Zero-Knowledge Proofs over Twisted ElGamal on Curve25519 with Ristretto Points.

Curve25519 using Ristretto Points provide a robust and high security level (strong 128 bits). It is also really fast to do homomorphic operations over those points. 

## Features

Support of following transactions types:
- Burn: ability to burn a public amount of requested asset from an encrypted balance without revealing it.
- Transfers: send to one or more destinations any asset / amount.
- Smart Contract: ability to transfers plaintext amounts using confidentials assets and encrypted balances to a Smart Contract / Public account.
- Multi-Sig: Secure a wallet behind more than one keypair by providing off-chain approvals integrated in the TX directly.

Support of Confidential Assets (spend any asset available, not just the "native coin").

Miner fee is also supported in transaction and can be decreased publicly from the sender address.

We are grouping each asset into "source commitments" to decrease only one time per asset the sender balance.
So, even if you create N transfers with the same asset being spent, it will operate only one subtraction from sender balance.

Range proofs aggregation is implemented and batching for fast verification, this is currently giving us (including Sigma Proofs) a ~0.40 ms verification time per TX over 100 transactions batched.