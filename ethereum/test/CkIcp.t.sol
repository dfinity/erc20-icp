// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "forge-std/Test.sol";
import "../src/CkIcp.sol";

contract CkIcpTest is Test {
    CkIcp public ckicp;

    function ckIcpSetup() public {
        ckicp = new CkIcp(address(0x04));
    }

}
