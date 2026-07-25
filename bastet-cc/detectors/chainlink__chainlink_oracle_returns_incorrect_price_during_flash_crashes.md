---
id: chainlink__chainlink_oracle_returns_incorrect_price_during_flash_crashes
name: "Chainlink-Oracle Returns Incorrect Price During Flash Crashes"
source_workflow: chainlink
upstream_model: gpt-4o-mini
tags: ["Chainlink", "Oracle", "Bad Randomness"]
routing_hints: ["feeds"]
prompt_chars: 2620
---

# Chainlink-Oracle Returns Incorrect Price During Flash Crashes

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Oracle Returns Incorrect Price During Flash Crashes**
Chainlink price feeds have in-built minimum & maximum prices they will return; if during a flash crash, bridge compromise, or depegging event, an asset’s value falls below the price feed’s minimum price, the oracle price feed will continue to report the (now incorrect) minimum price.

An attacker could:

buy that asset using a decentralized exchange at the very low price,
deposit the asset into a Lending / Borrowing platform using Chainlink’s price feeds,
borrow against that asset at the minimum price Chainlink’s price feed returns, even though the actual price is far lower.
This attack would let the attacker drain value from Lending / Borrowing platforms. To help mitigate such an attack on-chain, smart contracts could check that minAnswer < receivedAnswer < maxAnswer.

This attack could also potentially be mitigated off-chain via off-chain monitoring, which compares Chainlink’s latest reported price to other off-chain sources such as centralized exchanges and/or liquid indexes which aggregate multiple off-chain price sources to produce one index price; if external sources are reporting prices lower than Chainlink’s minAnswer, off-chain monitoring could disable the smart contract’s price feed for that asset, forcing any transactions to revert.

**Suggestion**

Developers & Auditors can find Chainlink’s oracle feed [minAnswer, maxAnswer] values by:

looking up the price feed address on Chainlink’s list of Ethereum mainnet price feeds (or select other L1/L2 for price feeds on other networks),
reading the “aggregator” value, e.g., for AAVE / USD price feed,
reading the minAnswer & maxAnswer values from the aggregator contract

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
