---
id: slippage__slippage_on_chain_slippage_calculation_can_be_manipulated
name: "Slippage-On-Chain Slippage Calculation Can Be Manipulated"
source_workflow: slippage
upstream_model: gpt-4o-mini
tags: ["Slippage"]
routing_hints: ["address", "balanceOf", "block.timestamp", "encodePacked", "exactInput", "quoteExactInput", "safeIncreaseAllowance", "swapTokensMulti"]
prompt_chars: 2880
---

# Slippage-On-Chain Slippage Calculation Can Be Manipulated

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**On-Chain Slippage Calculation Can Be Manipulated**
Developers should ensure & auditors must verify that users are allowed to specify their own slippage parameters which were calculated off-chain.

### Examples

#### Example 1

Consider this simplified code from Sherlock's Olympus Update contest

```solidity
function swapTokensMulti(
    SwapInOut memory                 _swap,
    IController.UniswapParams memory _uniswap,
    bool                             _rewardSwap
    ) public returns (uint256) {
    IERC20(_swap.tokenIn).safeIncreaseAllowance(_uniswap.router, _swap.amount);

    // @audit on-chain slippage calculation can be manipulated,
    // Quoter.quoteExactInput() itself does a swap!
    // https://github.com/Uniswap/v3-periphery/blob/main/contracts/lens/QuoterV2.sol#L138-L146
    // amountOutMinimum must be specified by user, calculated off-chain
    uint256 amountOutMinimum = IQuoter(_uniswap.quoter).quoteExactInput(
      abi.encodePacked(_swap.tokenIn, _uniswap.poolFee, WETH, _uniswap.poolFee, _swap.tokenOut),
      _swap.amount
    );

    uint256 balanceBefore = IERC20(_swap.tokenOut).balanceOf(address(this));
    if (_rewardSwap && balanceBefore > amountOutMinimum) return amountOutMinimum;

    ISwapRouter.ExactInputParams memory params = ISwapRouter.ExactInputParams({
      path: abi.encodePacked(
        _swap.tokenIn,
        _uniswap.poolFee,
        WETH,
        _uniswap.poolFee,
        _swap.tokenOut
      ),
      recipient: address(this),
      deadline: block.timestamp,
      amountIn: _swap.amount,
      amountOutMinimum: amountOutMinimum
    });

    ISwapRouter(_uniswap.router).exactInput(params);
    uint256 balanceAfter = IERC20(_swap.tokenOut).balanceOf(address(this));

    return balanceAfter - balanceBefore;
}
```

This code attempts to perform on-chain slippage calculation by using Quoter.quoteExactInput() which itself performs a swap and hence is subject to manipulation via sandwich attacks.

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
