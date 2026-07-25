---
id: erc4626__erc4626_global_and_user_specific_limits
name: "ERC4626-Global and user-specific limits"
source_workflow: erc4626
upstream_model: gpt-4o-mini
tags: ["ERC4626"]
routing_hints: ["deactivated", "deposit", "maxDeposit", "maxMint", "maxRedeem", "maxWithdraw", "nonReentrant", "previewDeposit", "type"]
prompt_chars: 2177
---

# ERC4626-Global and user-specific limits

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Global and user-specific limits**
When implementing a vault, it may happen that certain functions in the vault may be suspended due to urgent withdrawals or intentional by design, and some functions need to take into account these global state changes or user-specific restrictions.

### Examples

#### Example 1: Incorrect Example

Check out the following sample code:

```solidity
function deposit(uint256 assets, address receiver) external nonReentrant whenNotPaused returns (uint256) {
        uint256 shares = previewDeposit(assets);
        require(shares > 0, "ZERO_SHARES");
        /// .... [skipped the code]
    }
function maxDeposit(address) public view virtual returns (uint256) {
        return type(uint256).max;
    }
```

whenTokenNotPaused's modifier checks if the state at which deposit() was executed, and if the vault happens to be paused, maxDeposit() returns a value that can't actually be deposited, causing any component that relies on these functions to pass back the correct value to fail.

**Suggestion**

According to EIP 4626, maxDeposit(), maxMint(), maxWithdraw(), and maxRedeem() need to be taken into account global state or user-specific restrictions, and must be passed back to 0 if completely deactivated (even temporarily).

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
