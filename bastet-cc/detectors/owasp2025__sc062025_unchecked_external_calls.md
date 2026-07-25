---
id: owasp2025__sc062025_unchecked_external_calls
name: "SC06:2025 - Unchecked External Calls"
source_workflow: owasp2025
upstream_model: gpt-4o-mini
tags: ["call / delegatecall"]
routing_hints: ["call", "constructor", "delegatecall", "forward", "msg.sender", "send", "succeeds", "transfer"]
prompt_chars: 2964
---

# SC06:2025 - Unchecked External Calls

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Unchecked External Calls**
Unchecked external calls refer to a security flaw where a contract makes an external call to another contract or address without properly checking the outcome of that call. In Ethereum, when a contract calls another contract, the called contract can fail silently without throwing an exception. If the calling contract doesn’t check the return value, it might incorrectly assume the call was successful, even if it wasn’t. This can lead to inconsistencies in the contract state and vulnerabilities that attackers can exploit.

### Examples

#### Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.4.24;

contract Solidity_UncheckedExternalCall {
    address public owner;

    constructor() public {
        owner = msg.sender;
    }

    function forward(address callee, bytes _data) public {
        require(callee.delegatecall(_data));
    }
}
```

Impact:
*Unchecked external calls can result in failed transactions, causing the intended operations to not be completed successfully. This can lead to the loss of funds, as the contract may proceed under the false assumption that the transfer was successful. *Additionally, it can create an incorrect contract state, making the contract vulnerable to further exploits and inconsistencies in its logic.

#### Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0; 

contract Solidity_UncheckedExternalCall {
    address public owner;

    constructor() {
        owner = msg.sender;
    }

    function forward(address callee, bytes memory _data) public {
        // Ensure that delegatecall succeeds
        (bool success, ) = callee.delegatecall(_data);
        require(success, "Delegatecall failed");  // Check the return value to handle failure
    }
}
```


**Suggestion**

*Whenever possible, use transfer() instead of send(), as transfer() reverts the transaction if the external call fails.
*Always check the return value of send() or call() functions to ensure proper handling if they return false.

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
