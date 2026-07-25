---
id: chainlink__chainlink_oracle_price_feeds_not_updated_frequently
name: "Chainlink-Oracle Price Feeds Not Updated Frequently"
source_workflow: chainlink
upstream_model: gpt-4o-mini
tags: ["Chainlink", "Oracle", "Bad Randomness"]
routing_hints: ["_isPoolSafe", "_valueCollateral", "hours"]
prompt_chars: 2838
---

# Chainlink-Oracle Price Feeds Not Updated Frequently

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Oracle Price Feeds Not Updated Frequently**
If the selected price feed is not updated frequently enough, the contract may use outdated prices that deviate from the actual market prices.

### Examples

#### Example 1: Incorrect Example

oracle is using the HEARTBEAT_TIME as 24 hours. Since the price of oracle could vary in the time gap of 3 hours, using 24 hours could be still dangerous.

```solidity
uint256 private constant HEARTBEAT_TIME = 24 hours; //Check heartbeat frequency when adding new feeds
```

In this example, the first price feed has a heartbeat of 1 hour while the second has a heartbeat of 24 hours, so they require different heartbeats to be used in their staleness checks. 

#### Example 2: Incorrect Example

The _isPoolSafe() function checks if the balancer pool spot price is within the boundaries defined by THRESHOLD respect to the last fetched chainlink price.

Since in _valueCollateral() the updateThreshold should be 24 hours (as in the tests), then the OHM derived oracle price could stay at up to 2% from the on-chain trusted price. The value is 2% because in WstethLiquidityVault.sol#L223:

```solidity
return (amount_ * stethPerWsteth * stethUsd * decimalAdjustment) / (ohmEth * ethUsd * 1e18);
```

stethPerWsteth is mostly stable and changes in stethUsd and ethUsd will cancel out, so the return value changes will be close to changes in ohmEth, so up to 2% from the on-chain trusted price.

If THRESHOLD < 2%, say 1% as in the tests, then the Chainlink price can deviate by more than 1% from the pool spot price and less than 2% from the on-chain trusted price fro up to 24 h. During this period withdrawals and deposits will revert.


**Suggestion**

Smart contracts developers should use & auditors should check that price feeds with the lowest heartbeat & deviation thresholds are being used to ensure the oracle’s reported price is as close as possible to the true, current price.

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
