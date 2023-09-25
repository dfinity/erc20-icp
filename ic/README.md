# ckICP Main Canister

ckICP Main canister on the Internet Computer.

# Architecture

The ICP part is a _minter_ canister.

## Minter Canister

This canister is responsible for issuing minting signatures using tECDSA, and transferring
ICP when it is notified about Ethereum blocks that has the burned ICP event logs.

```
mint_ckicp:
    1. ICRC2 transfer
    2. generate tecdsa signature
process_block:
    1. read event logs of the given block hash (via ETH RPC canister)
    2. record event uid
    3. transfer ICP
```

## ICP -> ckICP User Flow

1. User has an ETH wallet with some ETH in it, and an ICP wallet with some ICP in it.
2. Call `mint_ckicp` of the ckICP minter canister.
3. Wait to get signature (if the call fails, calculate `MsgId` deterministically, then use `MsgId` to query for signature).
4. Use the signature to call `selfMint` of the ckICP ETH contract.
5. Get ckICP in return.

## ckICP -> ICP User Flow

1. User has ckICP in an ETH wallet, and an ICP wallet (can be empty).
2. Call `burn` or `burnToAccountId` of the ckICP ETH contract, and get the block hash.
3. Call `process_block` of the ckICP minter canister with the block hash.
4. Wait to get ICP in the ICP wallet.

# Deployment

## Minter Canister

# License

MIT
