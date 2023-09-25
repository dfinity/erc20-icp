// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "openzeppelin-contracts/token/ERC20/ERC20.sol";
import "openzeppelin-contracts/token/ERC20/extensions/ERC20Permit.sol";
import "openzeppelin-contracts/access/Ownable.sol";
import "openzeppelin-contracts/security/Pausable.sol";
import "openzeppelin-contracts/utils/cryptography/ECDSA.sol";

/// Contract for the ERC20 token that represents ICP on Ethereum.
/// The minter canister on the IC shall be the owner of this contract.
/// This contract shall be deployed deterministically to have the same address on every chain.
contract CkIcp is ERC20, ERC20Permit, Ownable, Pausable {
    using ECDSA for bytes32;

    uint8 public constant ICP_TOKEN_PRECISION = 8;
    mapping(uint256 => bool) public used;

    event SelfMint(uint256 indexed msgid);
    event BurnToIcp(uint256 amount, bytes32 indexed principal, bytes32 indexed subaccount);
    event BurnToIcpAccountId(uint256 amount, bytes32 indexed accountId);
    
    /// When deploying, set the owner to the minter canister on the IC
    constructor(address owner)
        ERC20("ICP token on Ethereum", "ICP")
        ERC20Permit("ICP token on Ethereum")
    {
        _transferOwnership(owner);
    }

    /// # Admin functions accessible to ckICP canister only

    /// Mint input amount is denominated in ICP e8s
    /// Mint output amount is denominated in wei
    /// Safety note: overflow not checked because minter can verify that prior to calling
    function mint(address to, uint256 amount) public onlyOwner {
        _mint(to, amount * 10**(decimals() - ICP_TOKEN_PRECISION));
    }

    /// # Public functions
    
    /// Anyone can mint by providing a valid signature from the minter (the owner of this contract)
    /// The signature must be over the following message:
    /// left_padded_32byte_concat(amount, to, msgId, expiry, chainId, address(this))
    /// Mint input amount is denominated in ICP e8s
    /// Mint output amount is denominated in wei
    /// Safety note: won't be frontrun because `to` is specified
    /// Safety note: overflow not checked because minter can verify that prior to signing
    function selfMint(uint256 amount, address to, uint256 msgid, uint64 expiry, bytes calldata signature) public whenNotPaused {
        require(block.timestamp < expiry, "Signature expired");
        require(!used[msgid], "MsgId already used");
        require(_verifyOwnerSignature(
            keccak256(abi.encode(amount, to, msgid, expiry, block.chainid, address(this))), 
            signature), "Invalid signature");
        used[msgid] = true;
        _mint(to, amount * 10**(decimals() - ICP_TOKEN_PRECISION));
        emit SelfMint(msgid);
    }

    /// Burn input amount is demoninated in wei
    /// Burn output amount is denominated in ICP e8s
    function burn(uint256 amount, bytes32 principal, bytes32 subaccount) public whenNotPaused {
        require(amount < (2**64 -1) * 10**(decimals() - ICP_TOKEN_PRECISION), "Amount too large");
        _burn(_msgSender(), amount);
        emit BurnToIcp(amount / 10**(decimals() - ICP_TOKEN_PRECISION), principal, subaccount);
    }

    function burnToAccountId(uint256 amount, bytes32 accountId) public whenNotPaused {
        require(amount < (2**64 -1) * 10**(decimals() - ICP_TOKEN_PRECISION), "Amount too large");
        _burn(_msgSender(), amount);
        emit BurnToIcpAccountId(amount / 10**(decimals() - ICP_TOKEN_PRECISION), accountId);
    }

    /// # Internal functions
    
    // Verify signature against a pure hash,
    // because tECDSA cannot generate EIP191 signatures
    function _verifyOwnerSignature(bytes32 hash, bytes calldata signature) internal view returns(bool) {
        return hash.recover(signature) == owner();
    }

    /// # Overrides
    function _mint(address to, uint256 amount) internal override(ERC20) {
        super._mint(to, amount);
    }

    function _burn(address from, uint256 amount) internal override(ERC20) {
        require(amount % 10**(decimals() - ICP_TOKEN_PRECISION) == 0, "Amount must not have significant figures beyond ICP token precision");
        super._burn(from, amount);
    }
}
