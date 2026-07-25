---
id: slippage__slippage_minting_exposes_users_to_unlimited_slippage
name: "Slippage-Minting Exposes Users To Unlimited Slippage"
source_workflow: slippage
upstream_model: gpt-4o-mini
tags: ["Slippage"]
routing_hints: ["_update", "address", "calculateSwap", "createSynth", "getReserves", "int128", "mint", "mintSynth", "remove_liquidity_one_coin", "safeTransferFrom", "synths", "tokens"]
prompt_chars: 2958
---

# Slippage-Minting Exposes Users To Unlimited Slippage

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Minting Exposes Users To Unlimited Slippage**
DeFi protocols allow users to transfer foreign tokens to mint the protocol's native token - this is functionally the same as a swap where users are swapping foreign tokens for the protocol's native token. Since this is packaged and presented as a "mint", a slippage parameter may be omitted exposing the user to unlimited slippage.

### Examples

#### Example 1

```solidity
function mintSynth(IERC20 foreignAsset, uint256 nativeDeposit,
                   address from, address to) returns (uint256 amountSynth) {
    // @audit transfers in foreign token
    nativeAsset.safeTransferFrom(from, address(this), nativeDeposit);

    ISynth synth = synthFactory.synths(foreignAsset);

    if (synth == ISynth(_ZERO_ADDRESS))
        synth = synthFactory.createSynth(
            IERC20Extended(address(foreignAsset))
        );

    // @audit frontrunner could manipulate these reserves to influence
    // amount of minted tokens
    (uint112 reserveNative, uint112 reserveForeign, ) = getReserves(
        foreignAsset
    ); // gas savings

    // @audit mints protocol's tokens based upon above reserves
    // this is effectively a swap without allowing the user to
    // specify a slippage parameter, exposing user to unlimited slippage
    amountSynth = VaderMath.calculateSwap(
        nativeDeposit,
        reserveNative,
        reserveForeign
    );

    _update(
        foreignAsset,
        reserveNative + nativeDeposit,
        reserveForeign,
        reserveNative,
        reserveForeign
    );

    synth.mint(to, amountSynth);
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

When implementing minting functions based upon pool reserves or other on-chain data that can be manipulated in real-time, developers should provide & auditors should verify that users can specify slippage parameters, as such mints are effectively swaps by another name.

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
