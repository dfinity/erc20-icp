# ckicp-ethereum-contracts
Ethereum contracts for ckICP

## Description
Ethereum contracts to be owned by the ckICP main canister on ICP via tECDSA.

## Functionalities
- [x] ERC20 tokens of ICP on Ethereum
- [x] Only the ckICP canister can mint
- [x] Anyone can burn ckICP on ETH to get ICP on the IC blockchain
- [x] EIP-2612

## Toolchain
https://github.com/foundry-rs/foundry

## Deterministic Deployment
1. Run `foundryup` and install the foundry toolchain.
1. Replace the `0x04` with the minter's Ethereum address in script/CkIcp.s.sol in line `new CkIcp{salt: bytes32(uint256(1))}(address(0x04));`.
1. Register an Etherscan account and export `ETHERSCAN_API_KEY`.
1. For mainnet deployment: change `eth_rpc_url` and `chain_id` in `foundry.toml`.
1. Run `forge script script/CkIcp.s.sol -v --private-key $DEPLOYER_SK --broadcast --etherscan-api-key $ETHERSCAN_API_KEY --verify`.
1. The Airdrop.sol does not need a deterministic address and can be deployed using `forge create --private-key $DEPLOYER_SK src/Airdrop.sol:Airdrop --etherscan-api-key $ETHERSCAN_API_KEY --verify`.
1. Commit `broadcast/CkIcp.s.sol/{chain_id}/*.json` back to this repo.

