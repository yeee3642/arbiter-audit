You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Hard-coded Slippage May Freeze User Funds**
The idea of setting slippage is to protect the user from getting less tokens than they wanted due to high volatility and stop them from being exploited by MEV bots. So why don't projects just hard-code low slippage to protect users? Because hard-coded slippage can freeze user funds during periods of high volatility.

### Examples

#### Example 1

Consider this simplified code from Sherlock's Olympus Update contest

```solidity
function withdrawCollateral(
    address _asset,
    uint256 _amount,
    address _to
) external virtual {
    // Before withdraw from lending pool, get the stAsset address and withdrawal amount
    // Ex: In Lido vault, it will return stETH address and same amount
    (address _stAsset, uint256 _stAssetAmount) = _getWithdrawalAmount(_asset, _amount);

    // withdraw from lendingPool, it will convert user's aToken to stAsset
    uint256 _amountToWithdraw = ILendingPool(_addressesProvider.getLendingPool()).withdrawFrom(
        _stAsset,
        _stAssetAmount,
        msg.sender,
        address(this)
    );

    // Withdraw from vault, it will convert stAsset to asset and send to user
    // Ex: In Lido vault, it will return ETH or stETH to user
    uint256 withdrawAmount = _withdrawFromYieldPool(_asset, _amountToWithdraw, _to);

    if (_amount == type(uint256).max) {
        uint256 decimal = IERC20Detailed(_asset).decimals();
        _amount = _amountToWithdraw.mul(this.pricePerShare()).div(10**decimal);
    }
    // @audit hard-coded slippage can cause all withdrawals to revert during
    // times of high volatility, freezing user funds. Users should have the option to
    // withdraw during high volatility by setting their own slippage.
    require(withdrawAmount >= _amount.percentMul(99_00), Errors.VT_WITHDRAW_AMOUNT_MISMATCH);

    emit WithdrawCollateral(_asset, _to, _amount);
}
```

This code sets a very small slippage on withdrawals. While this may protect users from losing funds due to slippage, during times of high volatility when slippage is unavoidable, it will also cause all withdrawals to revert, freezing user funds.

**Suggestion**

If a project uses a default slippage, users should always be able to override it with their own slippage to ensure they can transact even during times of high volatility.

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