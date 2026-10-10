Retrieved 2026-10-10 from https://docs.metamask.io/embedded-wallets/infrastructure/sss-architecture/ (markdown version, .md)

> For the complete documentation index, see [llms.txt](/llms.txt).

# Embedded Wallets' Shamir Secret Sharing Architecture

This document provides an in-depth exploration of the technical architecture of the [Shamir's Secret Sharing](/embedded-wallets/infrastructure/glossary/#shamir-secret-sharing) (SSS)-based SDKs, this includes the current Plug and Play and Single Factor Auth Mobile SDKs.

SSS is a base form of Multi-Party Computation (MPC) that splits a secret into `n` shares, of which threshold `t` are required to reconstruct the secret.

note

Alternatively, consider the [MPC architecture ](/embedded-wallets/infrastructure/mpc-architecture/) which does not fully-reconstruct the key.

| SDK Family                                         | Key Model                                                                                                             | Available from                                                    |
| -------------------------------------------------- | --------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------------- |
| [**Embedded Wallet SDKs**](/embedded-wallets/sdk/) | [SSS](/embedded-wallets/infrastructure/sss-architecture/) (key reconstruction)                                        | [Base, Growth, and Scale plans](https://web3auth.io/pricing.html) |
| **MPC Core Kit SDK**                               | [TSS/MPC](/embedded-wallets/infrastructure/mpc-architecture/#threshold-signature-scheme-key)  (no key reconstruction) | [Enterprise plan](https://web3auth.io/pricing.html)               |

## Components[​](#components "Direct link to Components")

The accompanying image illustrates the typical flow of wallet management within the SSS infrastructure.

![SSS Flow and Components](/assets/images/sss-architecture-flow-bc0cb13a8c2d9197ad844f2e4ff51ea3.png) 

### Auth nodes (enabling social login)[​](#auth-nodes-enabling-social-login "Direct link to Auth nodes (enabling social login)")

Auth nodes provide a user-specific key based on some form of attestation from the user. This attestation could come in the form of an OAuth login from an existing account, a traditional email account login, or even biometrics. Nodes need not return a private key, but need to fulfill the interface:

- `retrievePubKey()`
- `encrypt(msg,pubKey)`
- `decrypt(msg)`
- `sign(msg)`

For ease of illustration the rest of this document assumes that this is implemented with secp256k1 keys and ECIES. The key retrieved from the nodes is referred to as an encryption key or `encKey`.

### Storage layer[​](#storage-layer "Direct link to Storage layer")

The storage layer serves as a persistent data store for storing encrypted metadata. Examples of such systems include IPFS, Arweave, Sia, or even Byzantine Fault Tolerant (BFT) layers. Data availability and cost are the main factors to consider but the choice of storage layer is ultimately up to the implementer.

Our SSS infrastructure utilizes `encKey` from the nodes as an entry point to retrieve the private key. `encKey` is used to retrieve encrypted user-specific data from the storage layer, referred to as metadata. This data includes a user's threshold, polynomial commitments, associated devices, and so on.

### User device[​](#user-device "Direct link to User device")

The SSS infrastructure is dependent on user devices to store shares. The base flow accommodates a single device, but users can use multiple devices to increase the threshold once they have an initial setup. Access to device storage on the user's device is implementation specific. For example, for native applications on mobile, they can make use of the device keychain.

### Recovery share[​](#recovery-share "Direct link to Recovery share")

This is generally _not_ used during normal operation, and is intended for use in key recovery / share refresh if the user loses their device or shares.

## Flows[​](#flows "Direct link to Flows")

### Key handling on user login[​](#key-handling-on-user-login "Direct link to Key handling on user login")

Key handling begins in response to a user-triggered action, such as logging in. At this stage, the system attempts to retrieve any existing encrypted metadata associated with the user.

If metadata is found, the user is an existing user. The metadata is decrypted using the nodes' `encKey` , and the stored information is used to validate the user and load the existing secret-sharing parameters. No new key material is generated in this path.

If no metadata is found, the user is treated as a new user, and a new key is initialized. In this case, a 2-of-3 Shamir's Secret Sharing (SSS) polynomial is generated, producing a private key and its corresponding shares.

We select a polynomial `f(z)` over `Zq​` where: `f(z)=a1​z+σ`

- `f(0)=σ` denotes the private key scalar to be used by the user
- `a1​` is a polynomial coefficient to `z`
- `f(z1​),f(z2​)` and `f(z3​)` are ShareA, ShareB, and ShareC respectively
![Key Initialisation Flow](/assets/images/key-initialisation-sss-flow-2a6bc7166ff17cee110ce47613b624b8.png) 

ShareA is stored on the user's device, ShareB is encrypted with the `encKey` and stored on the storage layer for future retrieval, and ShareC dependent on user input or handled as a recovery share.

### Key reconstruction[​](#key-reconstruction "Direct link to Key reconstruction")

![Key Reconstruction Flow](/assets/images/key-reconstruction-sss-flow-ec3dcd140892f29c1423a585010fc74e.png) 

If a user has logged in previously, they reconstruct their key by decrypting ShareB (retrieved through the storage layer) and combining it with ShareA on the user's current device using [Lagrange interpolation](https://brilliant.org/wiki/lagrange-interpolation/#:~:text=Lagrange%20Interpolation,proof%20of%20the%20theorem%20below).

### Key generation with deterministic share[​](#key-generation-with-deterministic-share "Direct link to Key generation with deterministic share")

Provided with a user input, `input`, we can predetermine a single share in the generation of the SSS polynomial, where we peg ShareC or `f(z3​)` to a user's input. Let `H` be a cryptographically secure hash function. Given: `f(z3​)=H(input),select σ over Zq​ and solve a1​=z3​f(z3​)−σ​`.

In the case of secret resharing, we can also conduct the deterministic generation of the `f(z)` polynomial with a given `σ` and `input`. We are able to peg `n` given values to the key or shares as long as `n≤d+1` where `d` is the degree of the SSS polynomial `f(z)`.

It is important that `input` has sufficient entropy in its generation. A potential way to guarantee this is via using several security questions (for example a minnimum of three) with answers `A,B,C` to derive `input=A∣B∣C`. This can be implemented with a repository of questions, of which order and index can be defined in metadata.

Candidate qualified questions should have deterministic answers (such as, "your parent's birthday" or "your city of birth"), rather than "what's your favorite singer?". To accommodate for cases that users tend to forget their answers, there is a further potential of splitting the answers themselves via SSS such that the user can answer 3/5 questions, giving redundancy.

### Expanding the number of shares (adding a device)[​](#expanding-the-number-of-shares-adding-a-device "Direct link to Expanding the number of shares (adding a device)")

In the case of adding a new device, the user needs to migrate a share to the device to reconstruct their key. This can be done via user input or through a login to a current device.

![Expanding Shares Flow](/assets/images/expanding-shares-sss-flow-4993e12ebfa52fb71280e401bd3ca951.png) 

On reconstruction of `f(z)` on the new device, we set ShareD to `f(z4​)`.

### Share resharing and revocability[​](#share-resharing-and-revocability "Direct link to Share resharing and revocability")

Utilizing the storage layer, we are able to generate new shares for all devices, regardless if they are online or offline. This allows us to remove devices from the sharing, allow the user to change their security questions and/or adjust their security threshold. The key concept here is utilizing published share commitments as encryption keys to retrieve shares on the most updated SSS polynomial.

This is illustrated from a 2/4 SSS sharing `f(z)` with shares `sa​,sb​,sc​,sd​` kept on 3 user devices and the nodes. Let `g` be a generator of a multiplicative subgroup where the discrete log problem is assumed hard to solve. During initialization of the key we create share commitments `gsa​,gsb​,gsc​,gsd​` to be stored on the storage layer. These share commitments are analogous to public keys derived from the share scalars.

Given the user loses device D holding `sd​`, and wants to make that share redundant, they first reconstruct their key on device A. We utilize a public key-based encryption scheme (ECIES).

The user generates a new 2/3 SSS polynomial `h(z)` on the same `σ` with shares `s1​,s2​,s3​` and encrypts the newly generated shares for each respective share commitment, except for the lost `gsd​` commitment.

`for i={1,2,3} and v={a,b,c}encrypt(si​u,gsv​)⇒cnv​where nv={1a,2b,2c}` 

`cnv​`, the resulting ciphertext from the encryption, is then stored on the storage layer for retrieval on other devices.

On login to device B, the user retrieves `c2b​` is able to use `sb​` to decrypt the new `s2​` and reconstruct their key with `s1​` derived from the nodes in a similar fashion. Using the `h(z)` allows `sd` to also be deprecated as a share.

Resharing allows us to share a key on a new polynomial with a different degree/threshold, allowing us to also increase a user's security/factor devices or inputs to reconstruct their key as they require it. This can be incrementally done as needed.
