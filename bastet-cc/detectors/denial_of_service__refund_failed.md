---
id: denial_of_service__refund_failed
name: "Refund failed"
source_workflow: denial_of_service
upstream_model: gpt-4o-mini
tags: ["DoS"]
routing_hints: ["address", "safeTransfer", "tokens", "withdraw"]
prompt_chars: 2799
---

# Refund failed

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Refund failed**
This type of vulnerability often occurs when a smart contract attempts to refund funds to a previous user/contract, but the recipient cannot accept the refund, causing the contract's functionality to be permanently blocked.

### Examples

#### Example

The contract has a withdrawal function that distributes the specified funds proportionally to multiple recipients.

```solidity
function withdraw(uint256 amount, address[] memory recipients) external {
  require(recipients.length > 0, "No recipients provided");
  require(recipients.length <= 3, "Too many recipients");

  uint256 recipientAmount = amount / recipients.length;
  require(recipientAmount > 0, "Amount too small to split");

  for (uint256 i = 0; i < recipients.length; ++i) {
    require(recipients[i] != address(0), "Invalid recipient address");
    token.safeTransfer(recipients[i], recipientAmount);
  }
}
```

*Special ERC20 tokens
It is quite common for tokens to implement blacklists, and some tokens (such as USDC, USDT) have address blacklists controlled by contract-level administrators. If an address is blacklisted, transfers to or from that address will be prohibited.
A malicious or compromised token owner can trap funds in a contract by adding the contract address to a blacklist.

*ERC777 tokens compatible with ERC20
ERC777 is compatible with ERC20. ERC777 implements tokensReceived through the ERC1820 registry.
A malicious user could call tokensReceived and reject the token transfer, causing the transaction to fail and leaving the funds stranded.

Since safeTransfer is used in the loop, if a recipient in recipients is blacklisted, or a user using ERC777 as a recipient implements revert in tokensReceived, the withdrawal process will be blocked. Even if other recipients are normal and legal users, they will not be able to receive the money they deserve.

**Suggestion**

n/a

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
