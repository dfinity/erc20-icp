// SPDX-License-Identifier: MIT
pragma solidity 0.8.20;

import "openzeppelin-contracts/token/ERC20/IERC20.sol";
import "openzeppelin-contracts/access/Ownable.sol";
import "openzeppelin-contracts/security/ReentrancyGuard.sol";
import "./TransferHelper.sol";

contract Airdrop is Ownable, ReentrancyGuard {
    IERC20 public token;
    uint256 public preset_amount;

    constructor(IERC20 _token) {
        token = _token;
    }

    function airdrop(address[] calldata recipients, uint256[] calldata amounts) external onlyOwner nonReentrant {
        require(recipients.length == amounts.length, "Airdrop: Invalid input");
        for (uint256 i = 0; i < recipients.length; i++) {
            TransferHelper.safeTransfer(address(token), recipients[i], amounts[i]);
        }
    }

    function airdropPresetAmount(address[] calldata recipients) external onlyOwner nonReentrant {
        for (uint256 i = 0; i < recipients.length; i++) {
            TransferHelper.safeTransfer(address(token), recipients[i], preset_amount);
        }
    }

    function setPresetAmount(uint256 amount) external onlyOwner {
        preset_amount = amount;
    }

    function setTokenAddress(IERC20 _token) external onlyOwner {
        token = _token;
    }

}