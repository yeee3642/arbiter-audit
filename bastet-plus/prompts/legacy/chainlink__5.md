You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Assuming Oracle Price Precision**
When working with Oracle price feeds, developers must account for different price feeds having different decimal precision; it is an error to assume that every price feed will report prices using the same precision. Generally, non-ETH pairs report using 8 decimals, while ETH pairs report using 18 decimals.

If precision is assumed, there is plenty of room for developer mistakes to be made since, for example, ETH/USD reports using 8 decimals, as it is considered a non-ETH pair since the price of ETH is being reported in USD. There are also price feeds such as AMPL/USD that report using 18 decimals which breaks the general rule that USD price feeds report in 8 decimals.

**Suggestion**

Smart contracts can call AggregatorV3Interface.decimals() to get the exact number of decimals for the price feed being called.

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