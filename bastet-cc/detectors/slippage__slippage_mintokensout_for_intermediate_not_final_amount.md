---
id: slippage__slippage_mintokensout_for_intermediate_not_final_amount
name: "Slippage-MinTokensOut For Intermediate, Not Final Amount"
source_workflow: slippage
upstream_model: gpt-4o-mini
tags: ["Slippage"]
routing_hints: ["_exitBalancerPool", "address", "balanceOf", "getTknOhmPrice", "nonReentrant", "onlyOwner", "safeTransfer", "withdraw"]
prompt_chars: 3455
---

# Slippage-MinTokensOut For Intermediate, Not Final Amount

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**MinTokensOut For Intermediate, Not Final Amount**
Due to the composable nature of DeFi, a swap can execute multiple operations before returning the final amount of tokens to the user. If the "minTokensOut" parameter is used for an intermediate operation but not to check the final amount, this can result in a loss of funds vulnerability for the user since they may receive fewer tokens than specified.

### Examples

#### Example 1

Consider this simplified code from Sherlock's Olympus Update contest

```solidity
function withdraw(
    uint256            lpAmount_,
    uint256[] calldata minTokenAmounts_, // @audit slippage param
    bool               claim_
) external override onlyWhileActive onlyOwner nonReentrant returns (uint256, uint256) {
    // ...

    // @audit minTokenAmounts_ enforced here, but this is only
    // an intermediate operation not the final amount received by the user
    // Exit Balancer pool
    _exitBalancerPool(lpAmount_, minTokenAmounts_);

    // Calculate OHM and wstETH amounts received
    uint256 ohmAmountOut = ohm.balanceOf(address(this)) - ohmBefore;
    uint256 wstethAmountOut = wsteth.balanceOf(address(this)) - wstethBefore;

    // Calculate oracle expected wstETH received amount
    // getTknOhmPrice returns the amount of wstETH per 1 OHM based on the oracle price
    uint256 wstethOhmPrice = manager.getTknOhmPrice();
    uint256 expectedWstethAmountOut = (ohmAmountOut * wstethOhmPrice) / _OHM_DECIMALS;

    // @audit this is the final operation but minTokenAmounts_ is no longer
    // enforced, so the amount returned to the user may be less than the
    // minTokenAmounts_ specified, resulting in a loss of funds for the user
    //
    // Take any arbs relative to the oracle price for the Treasury and return the rest to the owner
    uint256 wstethToReturn = wstethAmountOut > expectedWstethAmountOut
        ? expectedWstethAmountOut
        : wstethAmountOut;
    if (wstethAmountOut > wstethToReturn)
        wsteth.safeTransfer(TRSRY(), wstethAmountOut - wstethToReturn);

    // ...
}
```

Here, the user-specified slippage parameter "minTokenAmounts_" is only enforced for the intermediate operation _exitBalancerPool(), after which the output amount of tokens can be further reduced by the treasury skimming the difference between the balancer & oracle expected return amount.


**Suggestion**

Developers & auditors should test & verify that the user-specified "minTokensOut" is always enforced at the final step of a swap before returning the tokens to the user.

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
