// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @notice Pure helper library: no state, no external calls, no funds.
///         Present in the benchmark purely to measure false positives.
library MerkleProof {
    function verify(bytes32[] memory proof, bytes32 root, bytes32 leaf) internal pure returns (bool) {
        return processProof(proof, leaf) == root;
    }

    function processProof(bytes32[] memory proof, bytes32 leaf) internal pure returns (bytes32) {
        bytes32 computedHash = leaf;
        for (uint256 i = 0; i < proof.length; i++) {
            computedHash = _hashPair(computedHash, proof[i]);
        }
        return computedHash;
    }

    function _hashPair(bytes32 a, bytes32 b) private pure returns (bytes32) {
        return a < b ? _efficientHash(a, b) : _efficientHash(b, a);
    }

    function _efficientHash(bytes32 a, bytes32 b) private pure returns (bytes32) {
        bytes32 value;
        assembly {
            mstore(0x00, a)
            mstore(0x20, b)
            value := keccak256(0x00, 0x40)
        }
        return value;
    }
}

library FixedPointMath {
    uint256 internal constant WAD = 1e18;

    function mulWadDown(uint256 x, uint256 y) internal pure returns (uint256) {
        return (x * y) / WAD;
    }

    function divWadDown(uint256 x, uint256 y) internal pure returns (uint256) {
        require(y != 0, "division by zero");
        return (x * WAD) / y;
    }

    function min(uint256 x, uint256 y) internal pure returns (uint256) {
        return x < y ? x : y;
    }
}
