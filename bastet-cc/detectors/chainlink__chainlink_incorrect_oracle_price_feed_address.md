---
id: chainlink__chainlink_incorrect_oracle_price_feed_address
name: "Chainlink-Incorrect Oracle Price Feed Address"
source_workflow: chainlink
upstream_model: gpt-4o-mini
tags: ["Chainlink", "Oracle", "Bad Randomness"]
routing_hints: ["constructor"]
prompt_chars: 2143
---

# Chainlink-Incorrect Oracle Price Feed Address

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Incorrect Oracle Price Feed Address**
Some projects will hard-code oracle price feed addresses. Others will have addresses in deploy scripts to be set during contract deployment. Wherever the addresses are located, auditors should check that they point to the correct oracle price feed.

### Examples

#### Example 1: Incorrect Example

```solidity
// @audit correct address here, but wrong address in constructor
// chainlink btc/usd priceFeed 0xf4030086522a5beea4988f8ca5b36dbc97bee88c;
contract StableOracleWBTC is IStableOracle {
    AggregatorV3Interface priceFeed;

    constructor() {
        priceFeed = AggregatorV3Interface(
            // @audit wrong address; this is ETH/USD not BTC/USD !
            0x5f4eC3Df9cbd43714FE2740f5E3616155c5b8419
        );
    }
```

Here the correct address for the BTC/USD price feed appears in the comment, but in the constructor, the address of the ETH/USD price feed incorrectly appears. 

**Suggestion**

Auditors should verify that price feed addresses are correct by referring to Chainlink’s list of Ethereum mainnet price feeds. For projects being deployed on L2s or alternate L1s, auditors should verify that correct price feed addresses are being used for those networks.

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
