# ERC20 ICP on Ethereum

This repository contains two parts enabling the ERC20 version of the ICP on Ethereum:

-   the ethereum ERC20 contract and
-   the escrow canister holding native ICP backing the ERC20 twins on Ethereum.

## How it works

The escrow canister [holds](https://dashboard.internetcomputer.org/account/a76029ec11a61dc169aad89f97cff95c4d3a13a0493a37bfea78290645517e72) at least as many native ICPs as currently [exist](https://etherscan.io/token/0x054b8f99d15cc5b35a42a926635977d62692f25b) in form of minted supply on Ethereum.
Whenever users want to mint new ERC20 tokens, they have to deposit native ICP into the minter canister.
Whenever ERC20 ICP gets burned, the escrow canister releases the corresponding amount of native ICP to the eligible recipient.

### Setup

The ERC20 ICP contract is [deployed](https://etherscan.io/token/0x054b8f99d15cc5b35a42a926635977d62692f25b) on the Ethereum mainnet and is controlled by the ICP escrow canister [deployed](https://a4gq6-oaaaa-aaaab-qaa4q-cai.raw.icp0.io/?id=gyfmy-eqaaa-aaaar-qabza-cai) to the IC mainnet.

### Minting

In order to mint new ERC20 ICP tokens on Ethereum, a user needs to:

-   deposit native ICP to the escrow canister,
-   receive a ECDSA signature back from canister allowing to mint new ERC20 tokens,
-   call into the ERC20 ICP contract with the received signature.

### Burning

In order to unwrap ERC20 tokens on Ethereum and get native ICP on IC, a user needs to:

-   have some ETH20 ICP tokens on their balance,
-   call the `burn` function of the ERC20 ICP contract with specifying an ICP address,
-   wait until the escrow canister on IC registers the burning event and transfers the burned amount of ICP to the provided ICP address.

See [this document](./ic/README.md) for more details about both flows.

## ERC20 ICP working name

In the presented source code, we refer to the ERC20 ICP by its working name ckICP.
This might change later.
