---
id: 4naly3er__4naly3er_h_get_dy_underlyingflashloan
name: "4naly3er-H-get_dy_underlyingFlashLoan"
source_workflow: 4naly3er
upstream_model: gpt-4o-mini
tags: ["Flashloan"]
routing_hints: ["get_dy_underlying", "latestAnswer"]
prompt_chars: 2870
---

# 4naly3er-H-get_dy_underlyingFlashLoan

## Detection prompt

You are a smart contract auditor, you should strictly follow the following steps to detect **using `get_dy_underlying()` as a price oracle** in the given contract code.

### `get_dy_underlying()` Used as a Price Oracle in Smart Contracts

The function `get_dy_underlying()` calculates the price based on the contract’s underlying reserves, which can be manipulated by sandwiching the call with a flash loan. Using this function as a price oracle is unsafe and may lead to financial losses. Instead, developers should use a Chainlink oracle or another trusted price feed to obtain reliable price information.

### Detection Process

1. **Initial Filtering Using Regular Expression**

   - First, scan the smart contract code for occurrences of the following pattern:
     ```
     /get_dy_underlying\(/gi
     ```
   - This regex identifies instances where `get_dy_underlying()` is used in the contract.
   - If no matches are found, output exactly: **"There’s no such issue."**
   - If a match is found, proceed to step 2.

2. **Manual Review for Unsafe Use of `get_dy_underlying()`**

   - Verify whether `get_dy_underlying()` is being used as a price oracle for critical financial operations.
   - Check if the contract implements measures to prevent price manipulation via flash loans.
   - Ensure that alternative secure price feeds, such as Chainlink oracles, are used when necessary.

### Issue Examples

#### Example 1: **Unsafe Use of `get_dy_underlying()` for Pricing**

```solidity
uint256 price = curvePool.get_dy_underlying(fromToken, toToken, amount); // @audit Unsafe: price is derived from `get_dy_underlying()`
```

**Explanation:**
- The function `get_dy_underlying()` is used to determine the price, but it can be manipulated with a flash loan attack, leading to inaccurate pricing.

#### Example 2: **Safe Use with Chainlink Oracle**

```solidity
uint256 price = chainlinkOracle.latestAnswer(); // Secure price feed
```

**Explanation:**
- Instead of using `get_dy_underlying()`, the contract retrieves pricing information from a reliable oracle to prevent price manipulation.

### Task to Perform

Follow the examples above to examine each contract to check if `get_dy_underlying()` is incorrectly used as a price oracle. The process should first scan using the regex filter and then proceed to analyze the contract logic.

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
