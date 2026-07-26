You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**No Slippage Parameter**
When submitting a token swap request, users should specify the minTokensOut parameter, which defines the minimum expected output amount. Setting this parameter to 0 means the user accepts any output amount, making them highly vulnerable to front-running or sandwich attacks, especially in high-volatility or low-liquidity scenarios, potentially leading to significant losses.

### Examples

#### Example 1: Incorrect Example

This code tells the swap that the user will accept a minimum amount of 0 output tokens from the swap, opening up the user to a catastrophic loss of funds via MEV bot sandwich attacks

```solidity
IUniswapRouterV2(SUSHI_ROUTER).swapExactTokensForTokens(
    toSwap,
    0, // @audit min return 0 tokens; no slippage => user loss of funds
    path,
    address(this),
    now
);
```

**Suggestion**

Platforms must allow users to specify a slippage parameter and set a reasonable minimum acceptable return amount.
If the user does not specify a value, a safe and reasonable default should be provided, but users must have the option to override the default.

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