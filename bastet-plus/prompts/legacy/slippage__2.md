You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Incorrect Slippage Calculation**
The slippage parameter should be something like "minTokensOut" - the minimum amount of tokens the user will accept for the swap. Anything else is a red flag to watch out for as it will likely constitute an incorrect slippage parameter.

### Examples

#### Example 1

```solidity
function withdraw(address _recipient, address _asset, uint256 _amount
) external onlyVault nonReentrant {
    // ...

    // Calculate how much of the pool token we need to withdraw
    (uint256 contractPTokens, , uint256 totalPTokens) = _getTotalPTokens();

    uint256 poolCoinIndex = _getPoolCoinIndex(_asset);
    // Calculate the max amount of the asset we'd get if we withdrew all the
    // platform tokens
    ICurvePool curvePool = ICurvePool(platformAddress);
    uint256 maxAmount = curvePool.calc_withdraw_one_coin(
        totalPTokens,
        int128(poolCoinIndex)
    );

    // Calculate how many platform tokens we need to withdraw the asset amount
    uint256 withdrawPTokens = totalPTokens.mul(_amount).div(maxAmount);

    // Calculate a minimum withdrawal amount
    uint256 assetDecimals = Helpers.getDecimals(_asset);
    // 3crv is 1e18, subtract slippage percentage and scale to asset
    // decimals
    // @audit not using user-provided _amount, but calculating a non-sensical
    // value based on the LP tokens
    uint256 minWithdrawAmount = withdrawPTokens
        .mulTruncate(uint256(1e18).sub(maxSlippage))
        .scaleBy(int8(assetDecimals - 18));

    curvePool.remove_liquidity_one_coin(
        withdrawPTokens,
        int128(poolCoinIndex),
        minWithdrawAmount
    );

    // ...
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

Auditors should keep an eye out for any out-of-the-ordinary modifications that protocols make to user-specified slippage parameters.

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