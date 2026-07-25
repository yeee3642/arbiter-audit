---
id: owasp2025__sc012025_improper_access_control
name: "SC01:2025 - Improper Access Control"
source_workflow: owasp2025
upstream_model: gpt-4o-mini
tags: ["Access Control"]
routing_hints: ["_burn", "burn", "mapping", "onlyOwner"]
prompt_chars: 2981
---

# SC01:2025 - Improper Access Control

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Improper Access Control**
An access control vulnerability is a security flaw that allows unauthorized users to access or modify the contract’s data or functions. These vulnerabilities arise when the contract’s code fails to restrict access adequately based on user permission levels. Access control in smart contracts can relate to governance and critical logic, such as minting tokens, voting on proposals, withdrawing funds, pausing and upgrading the contracts, and changing ownership.

### Examples

#### Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract Solidity_AccessControl {
    mapping(address => uint256) public balances;

    // Burn function with no access control
    function burn(address account, uint256 amount) public {
        _burn(account, amount);
    }
}
```

Impact:
*Attackers can gain unauthorized access to critical functions and data within the contract, compromising its integrity and security.
*Vulnerabilities can lead to the theft of funds or assets controlled by the contract, causing significant financial damage to users and stakeholders.

#### Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Import the Ownable contract from OpenZeppelin to manage ownership
import "@openzeppelin/contracts/access/Ownable.sol";

contract Solidity_AccessControl is Ownable {
    mapping(address => uint256) public balances;

    // Burn function with proper access control, only accessible by the contract owner
    function burn(address account, uint256 amount) public onlyOwner {
        _burn(account, amount);
    }
}
```

**Suggestion**

*Ensure initialization functions can only be called once and exclusively by authorized entities.
*Use established access control patterns like Ownable or RBAC (Role-Based Access Control) in your contracts to manage permissions and ensure that only authorized users can access certain functions. This can be done by adding appropriate access control modifiers, such as onlyOwner or custom roles to sensitive functions.

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
