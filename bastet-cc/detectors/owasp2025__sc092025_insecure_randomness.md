---
id: owasp2025__sc092025_insecure_randomness
name: "SC09:2025 - Insecure Randomness"
source_workflow: owasp2025
upstream_model: gpt-4o-mini
tags: ["Bad Randomness"]
routing_hints: ["address", "balanceOf", "block", "block.number", "block.timestamp", "blockhash", "constructor", "encodePacked", "fulfillRandomness", "generator", "guess", "keccak256", "msg.sender", "oracles", "requestRandomNumber", "requestRandomness", "uint256"]
prompt_chars: 4998
---

# SC09:2025 - Insecure Randomness

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Insecure Randomness**
Random number generators are essential for applications like gambling, game-winner selection, and random seed generation. On Ethereum, generating random numbers is challenging due to its deterministic nature. Since Solidity cannot produce true random numbers, it relies on pseudorandom factors. Additionally, complex calculations in Solidity are costly in terms of gas.

Insecure Mechanisms Create Random Numbers in Solidity: Developers often use block-related methods to generate random numbers, such as:

*block.timestamp: Current block timestamp.
*blockhash(uint blockNumber): Hash of a given block (only for the last 256 blocks).
*block.difficulty: Current block difficulty.
*block.number: Current block number.
*block.coinbase: Address of the current block’s miner.

These methods are insecure because miners can manipulate them, affecting the contract’s logic.

### Examples

#### Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

contract Solidity_InsecureRandomness {
    constructor() payable {}

    function guess(uint256 _guess) public {
        uint256 answer = uint256(
            keccak256(
                abi.encodePacked(block.timestamp, block.difficulty, msg.sender) // Using insecure mechanisms for random number generation
            ) 
        );

        if (_guess == answer) {
            (bool sent,) = msg.sender.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
    }
}
```

Impact:
*Insecure randomness can be exploited by attackers to gain an unfair advantage in games, lotteries, and any other contracts that rely on random number generation. By predicting or manipulating the supposedly random outcomes, attackers can influence the results in their favor. This can lead to unfair wins, financial losses for other participants, and a general lack of trust in the smart contract’s integrity and fairness.

#### Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "@chainlink/contracts/src/v0.8/VRFConsumerBase.sol";

contract Solidity_InsecureRandomness is VRFConsumerBase {
    bytes32 internal keyHash;
    uint256 internal fee;
    uint256 public randomResult;

    constructor(address _vrfCoordinator, address _linkToken, bytes32 _keyHash, uint256 _fee) 
        VRFConsumerBase(_vrfCoordinator, _linkToken) 
    {
        keyHash = _keyHash;
        fee = _fee;
    }

    function requestRandomNumber() public returns (bytes32 requestId) {
        require(LINK.balanceOf(address(this)) >= fee, "Not enough LINK");
        return requestRandomness(keyHash, fee);
    }

    function fulfillRandomness(bytes32 requestId, uint256 randomness) internal override {
        randomResult = randomness;
    }

    function guess(uint256 _guess) public {
        require(randomResult > 0, "Random number not generated yet");
        if (_guess == randomResult) {
            (bool sent,) = msg.sender.call{value: 1 ether}("");
            require(sent, "Failed to send Ether");
        }
    }
}
```


**Suggestion**

*Using oracles (Oraclize) as external sources of randomness. Care should be taken while trusting the Oracle. Multiple Oracles can also be used.
*Using Commitment Schemes — A cryptographic primitive that uses a commit-reveal approach can be followed. It also has wide applications in coin flipping, zero-knowledge proofs, and secure computation. E.g.: RANDAO.
*Chainlink VRF — It is a provably fair and verifiable random number generator (RNG) that enables smart contracts to access random values without compromising security or usability.
*The Signidice Algorithm — Suitable for PRNG in applications involving two parties using cryptographic signatures.
*Bitcoin Block Hashes — Oracles like BTCRelay can be used which act as a bridge between Ethereum and Bitcoin. Contracts on Ethereum can request future block hashes from the Bitcoin Blockchain as a source of entropy. It should be noted that this approach is not safe against the miner incentive problem and should be implemented with caution.

### Task to Perform
Follow the examples above to examine each contract and check if it contains this issue. If you find any potential issues, record them using the format below.

### Output Format

If NO concrete vulnerability found, output a empty array

Otherwise, follow the format below:

```
[
    {
        "summary":  "summary of the vulnerabilities",
        "vulnerability_details": {
            "function_name": "Name of the function",
            "description": "a brief description of the vulnerability"
        },
    
        "code_snippet": [
            "code snippet in the file"
        ],
    
        "recommendation": "recommendation of how to fix the vulnerability"
    
    }
]
```

## Output schema

```json
{
  "type": "array",
  "items": {
    "type": "object",
    "properties": {
      "summary": {
        "type": "string",
        "description": "Brief summary of the vulnerability"
      },
      "severity": {
        "type": "string",
        "items": {
          "type": "string",
          "enum": ["high", "medium", "low"]
        },
        "description": "Severity level of the vulnerability"
      },
      "vulnerability_details": {
        "type": "object",
        "properties": {
          "function_name": {
            "type": "string",
            "description": "Function name where the vulnerability is found"
          },
          "description": {
            "type": "string",
            "description": "Detailed description of the vulnerability"
          }
        },
        "required": ["function_name", "description"]
      },
      "code_snippet": {
        "type": "array",
        "items": {
          "type": "string"
        },
        "description": "Code snippet showing the vulnerability",
        "default": []
      },
      "recommendation": {
        "type": "string",
        "description": "Recommendation to fix the vulnerability"
      }
    },
    "required": ["summary", "severity", "vulnerability_details", "code_snippet", "recommendation"]
  },
  "additionalProperties": false
}
```
