---
id: synth__compound
name: "Compound-Reward Manipulation via Exchange Rate"
source_workflow: synthesized
upstream_model: ais3/nemotron-3-ultra-550b
tags: ["Compound"]
routing_hints: ["Comptroller", "cToken", "CErc20", "exchangeRateStored", "borrowIndex", "CToken", "CTokenInterface", "ComptrollerInterface"]
required_hints: []
prompt_chars: 5707
synthesized: true
gated: true
synth_provenance: {"train_findings": [], "localization_rate": 0.0, "mode": "s2b", "hint_candidates": 27, "hints_rejected": 27, "hint_coverage": 1.0, "single_repo_hints": true, "hint_fallback": false, "loro": null}
---

# Compound-Reward Manipulation via Exchange Rate

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and detection checks, examine the contract code for this specific class of issue.

### Vulnerability Knowledge

**Compound-Reward Manipulation via Exchange Rate**
Compound v2 cTokens use an exchange rate (cToken/underlying) that increases over time as interest accrues. The rate is returned by `exchangeRateCurrent()` (or `exchangeRateStored()`) and is used to convert between underlying and cToken amounts in `mint`, `redeem`, `borrow`, and `repayBorrow`. If a protocol reads this rate inside a function that also transfers the underlying asset (e.g., a deposit that mints cTokens, or a withdrawal that redeems), an attacker can sandwich the call: donate underlying directly to the cToken contract just before the victim's transaction, inflating the exchange rate, then withdraw after the victim's mint/redeem executes at the manipulated rate. The vulnerability arises when the contract (1) relies on a spot exchange rate without a slippage bound, (2) performs the asset transfer and the rate-dependent calculation in the same transaction without reentrancy protection, or (3) allows the rate to be read after a user-controlled external call (e.g., `transferFrom` callback) that can donate to the cToken. Protocols integrating Compound must either snapshot the rate before any external call, enforce a maximum acceptable rate change, or use `mintFresh`/`redeemFresh` with explicit `amount` parameters that bypass rate conversion.

### Detection Checks

1. Function calls `cToken.exchangeRateCurrent()` or `exchangeRateStored()` and uses the returned value to compute mint/redeem/borrow/repay amounts without a user-supplied slippage limit.
2. Underlying token transfer (`transferFrom`, `safeTransferFrom`, `pullToken`) occurs before the exchange rate is read, allowing a donation to manipulate the rate seen by the subsequent mint/redeem.
3. External call to an untrusted address (e.g., `token.transferFrom(msg.sender, ...)`) precedes the rate read, and the token is the same underlying as the cToken, enabling a reentrant donation via ERC-777/677 callbacks.
4. Contract uses `cToken.mint()` or `redeem()` (which internally convert via exchange rate) instead of `mintFresh`/`redeemFresh` with explicit underlying amounts.
5. No check that `exchangeRateCurrent()` <= `expectedRate * (1 + maxSlippage)` before executing the state-changing operation.
6. Governance or admin function updates a cToken market address without timelock, allowing a malicious market with a manipulated rate to be swapped in.
7. Function reads `totalBorrows`/`totalReserves`/`cash` directly from the cToken and computes a custom rate instead of using the canonical `exchangeRateCurrent()`, introducing rounding or stale-data errors.
8. Liquidation or seize logic calls `cToken.seize()` without verifying that the seized cToken amount corresponds to the expected underlying value at a bounded exchange rate.

### Examples

#### Example 1: Incorrect Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
interface ICToken {
    function mint(uint256) external returns (uint256);
    function exchangeRateCurrent() external view returns (uint256);
    function underlying() external view returns (address);
}

contract VulnerableDeposit {
    ICToken public cDAI;
    IERC20 public DAI;

    function deposit(uint256 amount) external {
        // @audit rate read AFTER transferFrom; donation can inflate rate
        DAI.transferFrom(msg.sender, address(this), amount);
        uint256 rate = cDAI.exchangeRateCurrent(); // manipulated spot rate
        cDAI.mint(amount); // uses inflated rate -> fewer cTokens minted
    }
}
```

The deposit reads the exchange rate after pulling DAI, so a front-run donation to the cDAI contract inflates the rate and causes the user to receive fewer cTokens.

#### Example 2: Correct Example

```solidity
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.10;

interface IERC20 {
    function transferFrom(address, address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}
interface ICToken {
    function mintFresh(uint256, address, uint256) external returns (uint256);
    function exchangeRateCurrent() external view returns (uint256);
    function underlying() external view returns (address);
}

contract SafeDeposit {
    ICToken public cDAI;
    IERC20 public DAI;
    uint256 public constant MAX_SLIPPAGE_BPS = 50; // 0.5%

    function deposit(uint256 amount, uint256 minCTokens) external {
        uint256 rateBefore = cDAI.exchangeRateCurrent();
        DAI.transferFrom(msg.sender, address(this), amount);
        uint256 rateAfter = cDAI.exchangeRateCurrent();
        require(rateAfter <= rateBefore + (rateBefore * MAX_SLIPPAGE_BPS / 10000), "rate slipped");
        // mintFresh takes explicit underlying amount, bypassing rate conversion
        uint256 minted = cDAI.mintFresh(amount, msg.sender, minCTokens);
        require(minted >= minCTokens, "slippage exceeded");
    }
}
```

The fix snapshots the rate before the transfer, bounds the allowable rate change, and uses `mintFresh` with a user-supplied minimum cToken amount to eliminate rate manipulation.

### Task to Perform
Apply each detection check above to every contract function provided. Report only concrete instances of this vulnerability class, citing the specific check that failed and the offending lines.

### Output Format
If NO concrete vulnerability found, output a empty array
