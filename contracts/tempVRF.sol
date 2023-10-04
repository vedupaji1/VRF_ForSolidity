// SPDX-License-Identifier: LGPL 3.0
pragma solidity >=0.5.3 <0.7.0;

import "./VRF.sol";

contract temp {
    function verify(
        uint256[2] memory _publicKey,
        uint256[4] memory _proof,
        bytes memory _message
    ) external pure returns (bool) {
        return VRF.verify(_publicKey, _proof, _message);
    }

    function decodeProof(bytes memory _proof) external pure returns (uint[4] memory) {
        return VRF.decodeProof(_proof);
    }
}
