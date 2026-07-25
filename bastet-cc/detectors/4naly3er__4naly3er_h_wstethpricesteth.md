---
id: 4naly3er__4naly3er_h_wstethpricesteth
name: "4naly3er-H-wstETHPriceStEth"
source_workflow: 4naly3er
upstream_model: gpt-4o-mini
tags: ["Oracle"]
routing_hints: ["getPrice", "stEthPerToken"]
prompt_chars: 2841
---

# 4naly3er-H-wstETHPriceStEth

## Detection prompt

You are a smart contract auditor, you should strictly follow the following steps to detect the **Misuse of wstETH Units** issue in the given contract code.

### Detecting Misuse of `wstETH` Units in Smart Contracts

In Solidity, functions of the `wstETH` token operate using units of `stETH`, not `ETH`. This distinction is crucial because the price of `stETH` is not equivalent to the price of `ETH`, even after the Ethereum Shanghai upgrade. Failing to account for this difference can lead to incorrect calculations and potential financial loss.

### Detection Process

1. **Initial Filtering Using Regular Expression**

   - First, scan the smart contract code for occurrences of the following pattern:
     ```
     /(price.*\\*.*WstETH.*stEthPerToken|WstETH.*stEthPerToken.*\\*.*price)/gi
     ```
   - This regex identifies calculations that multiply `WstETH.stEthPerToken()` by `price`, which may imply incorrect assumptions about unit equivalence.
   - If no matches are found, output exactly: **"There’s no such issue."**
   - If a match is found, proceed to step 2.

2. **Manual Review for Incorrect Usage of `wstETH` Units**

   - Verify that calculations involving `wstETH` and `price` account for the difference between `stETH` and `ETH` units.
   - Ensure that the contract correctly converts `wstETH` values into `ETH` or `stETH` as needed.

### Issue Examples

#### Example 1: **Incorrect Use of `wstETH` in Pricing Calculation**

```solidity
uint256 price = getPrice();
uint256 value = price * WstETH.stEthPerToken();
```

**Explanation:**
- The calculation incorrectly assumes that `WstETH.stEthPerToken()` represents a value in `ETH`, leading to inaccurate results.

#### Example 2: **Correct Use with Unit Conversion**

```solidity
uint256 price = getPrice();
uint256 stEthAmount = WstETH.stEthPerToken();
uint256 ethEquivalent = (stEthAmount * price) / 1e18; // Correct conversion to maintain correct units
```

**Explanation:**
- The calculation converts `stETH` units into `ETH` by adjusting for decimal differences, ensuring accurate pricing.

### Task to Perform

Follow the examples above to examine each contract to check if `wstETH` functions are correctly used with unit conversions. The process should first scan using the regex filter and then proceed to analyze the contract logic.

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
