You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Same Heartbeat Used For Multiple Price Feeds**
When a smart contract uses multiple price feeds, it should not assume that all feeds have the same heartbeat interval.

### Examples

#### Example 1: Incorrect Example

Smart contracts often use multiple oracle price feeds to track prices for multiple assets. It is an error to assume that the same time interval heartbeat can be used as a staleness check for every feed, as different feeds can have different heartbeats

  ```solidity
function getMarkPrice() external view returns (uint256 price) {
  int256 rawPrice;
  uint256 updatedAt;
  // @audit first feed
  (, rawPrice, , updatedAt, ) = IChainlink(chainlink).latestRoundData();

  // @audit second feed
  (, int256 USDCPrice,, uint256 USDCUpdatedAt,) = IChainlink(USDCSource).latestRoundData();
  
  require( // @audit feed #1 stale check using same heartbeatInterval
  block.timestamp - updatedAt <= heartbeatInterval,
  "ORACLE_HEARTBEAT_FAILED"
  );       
           // @audit feed #2 stale check using same heartbeatInterval
  require(block.timestamp - USDCUpdatedAt <= heartbeatInterval, "USDC_ORACLE_HEARTBEAT_FAILED");
  uint256 tokenPrice = (SafeCast.toUint256(rawPrice) * 1e8) / SafeCast.toUint256(USDCPrice);
  return tokenPrice * 1e18 / decimalsCorrection;
}
  ```

In this example, the first price feed has a heartbeat of 1 hour while the second has a heartbeat of 24 hours, so they require different heartbeats to be used in their staleness checks. 


**Suggestion**

Use the heartbeat value displayed in the Chainlink list for each price feed individually to validate data freshness.

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