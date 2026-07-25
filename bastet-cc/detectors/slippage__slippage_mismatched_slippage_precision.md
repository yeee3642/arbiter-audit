---
id: slippage__slippage_mismatched_slippage_precision
name: "Slippage-Mismatched Slippage Precision"
source_workflow: slippage
upstream_model: gpt-4o-mini
tags: ["Slippage"]
routing_hints: ["_convertToToken", "_getGlpPrice", "address", "balanceOf", "decimals", "getMaxPrice", "int128", "mulDiv", "remove_liquidity_one_coin", "unstakeAndRedeemGlp"]
prompt_chars: 2749
---

# Slippage-Mismatched Slippage Precision

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Mismatched Slippage Precision**
Some platforms allow a user to redeem or withdraw from a set of output tokens with a wide range of different precision values. These platforms must ensure that the slippage parameter "minTokensOut" is scaled to match the precision of the selected output token, else the slippage parameter may be ineffective and lead to precision loss errors.

### Examples

#### Example 1

```solidity
function _convertToToken(address token, address receiver) internal returns (uint256 amountOut) {
    // this value should be whatever glp is received by calling withdraw/redeem to junior vault
    uint256 outputGlp = fsGlp.balanceOf(address(this));

    // using min price of glp because giving in glp
    uint256 glpPrice = _getGlpPrice(false);

    // using max price of token because taking token out of gmx
    uint256 tokenPrice = gmxVault.getMaxPrice(token);

    // @audit always returns 6 decimals, won't work for many tokens
    // apply slippage threshold on top of estimated output amount
    uint256 minTokenOut = outputGlp.mulDiv(glpPrice * (MAX_BPS - slippageThreshold), tokenPrice * MAX_BPS);
    // @audit need to adjust slippage precision to match output
    // token decimals like so:
    // minTokenOut = minTokenOut * 10 ** (token.decimals() - 6);

    // will revert if atleast minTokenOut is not received
    amountOut = rewardRouter.unstakeAndRedeemGlp(address(token), outputGlp, minTokenOut, receiver);
}
```

And the fixed version after the audit:

```solidity
curvePool.remove_liquidity_one_coin(
    withdrawPTokens,
    int128(poolCoinIndex),
    _amount
);
```


**Suggestion**

"minTokenOut" always returns 6 decimals but the user can specify an output token from a set with a wide range of different precisions, hence the slippage must be scaled to match the output token's precision.

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
