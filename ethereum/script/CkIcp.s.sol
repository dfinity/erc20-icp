// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Script.sol";
import "../src/CkIcp.sol";

contract CkIcpScript is Script {
    function setUp() public {}

    function run() public {
        vm.broadcast();
        new CkIcp{salt: bytes32(uint256(1))}(address(0xF70312ce27936b3E143c46eA5e5fa630737c14f0));
    }
}
