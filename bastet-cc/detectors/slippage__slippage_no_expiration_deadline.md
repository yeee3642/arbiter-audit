---
id: slippage__slippage_no_expiration_deadline
name: "Slippage-No Expiration Deadline"
source_workflow: slippage
upstream_model: gpt-4o-mini
tags: ["Slippage"]
routing_hints: ["_doCutRewardsFee", "_ensureApprove", "address", "block.timestamp", "swapExactTokensForTokens", "type"]
prompt_chars: 2554
---

# Slippage-No Expiration Deadline

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**No Expiration Deadline**
Advanced protocols like Automated Market Makers (AMMs) can allow users to specify a deadline parameter that enforces a time limit by which the transaction must be executed. Without a deadline parameter, the transaction may sit in the mempool and be executed at a much later time potentially resulting in a worse price for the user.

### Examples

#### Example 1: Incorrect Example

Here "minTokensOut" is hard-coded to 0 so the swap can potentially return 0 output tokens, and the deadline parameter is hard-coded to the max value of utint256, so the transaction can be held & executed at a much later & more unfavorable time to the user. This combination of No Slippage & No Deadline exposes the user to the potential loss of all their input tokens!

```solidity
// Swap rewards tokens to debt token
uint256 rewards = _doCutRewardsFee(CRV);
_ensureApprove(CRV, address(swapRouter), rewards);
swapRouter.swapExactTokensForTokens(
    rewards,
    0, // @audit no slippage, can receive 0 output tokens
    swapPath,
    address(this),
    type(uint256).max // @audit no deadline, transaction can 
    // be executed later at a more unfavorable time
);
```

**Suggestion**

Protocols shouldn't set the deadline to `block.timestamp` as a validator can hold the transaction and the block it is eventually put into will be `block.timestamp`, so this offers no protection.

Protocols should allow users interacting with AMMs to set expiration deadlines; no expiration deadline may create a potential critical loss of funds vulnerability for any user initiating a swap, especially if there is also no slippage parameter.

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
