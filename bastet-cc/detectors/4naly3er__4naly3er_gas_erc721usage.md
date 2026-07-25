---
id: 4naly3er__4naly3er_gas_erc721usage
name: "4naly3er-GAS-ERC721usage"
source_workflow: 4naly3er
upstream_model: gpt-4o-mini
tags: ["ERC721"]
routing_hints: ["_isApprovedOrOwner", "_mint", "_msgSender", "_payTxFee", "_safeMint", "_safeTransfer", "_transfer", "constructor", "mapping", "mint", "msg.sender", "safeTransferFrom", "setExcluded", "transferFrom"]
prompt_chars: 4547
---

# 4naly3er-GAS-ERC721usage

## Detection prompt

You are a smart contract auditor, you should strictly follow the following steps to detect the **ERC721 gas inefficiency** problem in the given contract code.

### ERC721 Gas inefficiency issue
In Solidity, using the ERC721 standard for NFT contracts can lead to higher gas costs, especially when minting multiple NFTs simultaneously. The ERC721A standard, introduced by the Azuki team, is a more gas-efficient alternative that allows developers to mint multiple NFTs with significantly lower gas consumption. This improvement is particularly beneficial in the context of Ethereum's high gas fees.

### Detection Process
1. Initial Filtering Using Regex

First, scan the smart contract code for occurrences of the following pattern:
`/import.+openz.+ERC721\.sol/gi`

If no matches are found, output exactly: "There’s no such issue."
If a match is found, proceed to step 2.

2. Manual Review for Gas Inefficiency

Check if the contract is using ERC721 without a justified reason.

Verify whether batch minting is required and if ERC721A could be a more efficient alternative.

### Gas Inefficiency Examples

#### Example 1: **Gas Inefficiency Present (Using ERC721)**

The following code contains a **Gas Inefficiency** issue since it uses the `ERC721` standard instead of `ERC721A`.

```solidity
//"SPDX-License-Identifier: MIT"

pragma solidity ^0.8.6;

import '@openzeppelin/contracts/token/ERC721/ERC721.sol';
import '@openzeppelin/contracts/token/ERC20/IERC20.sol';

contract NFT is ERC721 {
  address public artist;
  address public txFeeToken;
  uint public txFeeAmount;
  mapping(address => bool) public excludedList;

  constructor(
    address _artist, 
    address _txFeeToken,
    uint _txFeeAmount
  ) ERC721('My NFT', 'ABC') {
    artist = _artist;
    txFeeToken = _txFeeToken;
    txFeeAmount = _txFeeAmount;
    excludedList[_artist] = true; 
    _mint(artist, 0);
  }

  function setExcluded(address excluded, bool status) external {
    require(msg.sender == artist, 'artist only');
    excludedList[excluded] = status;
  }

  function transferFrom(
    address from, 
    address to, 
    uint256 tokenId
  ) public override {
     require(
       _isApprovedOrOwner(_msgSender(), tokenId), 
       'ERC721: transfer caller is not owner nor approved'
     );
     if(excludedList[from] == false) {
      _payTxFee(from);
     }
     _transfer(from, to, tokenId);
  }

  function safeTransferFrom(
    address from,
    address to,
    uint256 tokenId
   ) public override {
     if(excludedList[from] == false) {
       _payTxFee(from);
     }
     safeTransferFrom(from, to, tokenId, '');
   }

  function safeTransferFrom(
    address from,
    address to,
    uint256 tokenId,
    bytes memory _data
  ) public override {
    require(
      _isApprovedOrOwner(_msgSender(), tokenId), 
      'ERC721: transfer caller is not owner nor approved'
    );
    if(excludedList[from] == false) {
      _payTxFee(from);
    }
    _safeTransfer(from, to, tokenId, _data);
  }

  function _payTxFee(address from) internal {
    IERC20 token = IERC20(txFeeToken);
    token.transferFrom(from, artist, txFeeAmount);
  }
```

**Explanation:**

- The contract uses `ERC721` instead of the more gas-efficient `ERC721A` standard.

#### Example 2: **Gas-Efficient Code (Using ERC721A)**

The following code does not contain any **Gas Inefficiency** issue since it uses the `ERC721A` standard.

```solidity
import "erc721a/contracts/ERC721A.sol";

contract GasEfficientNFT is ERC721A {
    constructor() ERC721A("GasEfficientNFT", "GENFT") {}

    function mint(address to, uint256 quantity) external {
        _safeMint(to, quantity); // Efficient batch minting
    }
}
```

**Explanation:**

- The contract uses `ERC721A`, which is optimized for batch NFT minting.

### Task to Perform
Follow the examples above to examine each contract to check if it contains the **Gas Inefficiency** issue due to using `ERC721` instead of `ERC721A`. If you find instances of `ERC721` imports, record them using the format below.

### Output Format

If NO concrete vulnerability found, output a empty array

Otherwise, follow the format below:

```
[
    {
        "summary":  "summary of the vulnerabilities",
        "Vulnerability Details": {
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
