---
id: chainlink__chainlink_unhandled_depeg_of_bridged_assets
name: "Chainlink-Unhandled Depeg Of Bridged Assets"
source_workflow: chainlink
upstream_model: gpt-4o-mini
tags: ["Chainlink", "Oracle", "Bad Randomness"]
routing_hints: []
prompt_chars: 1729
---

# Chainlink-Unhandled Depeg Of Bridged Assets

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Unhandled Depeg Of Bridged Assets**
Consider a Lending & Borrowing protocol where:

users can deposit a wrapped asset such as WBTC (wrapped BTC) and borrow against it,
the protocol uses Chainlink’s BTC/USD feed to price WBTC,
If the WBTC bridge is compromised and WBTC depegs from BTC, the protocol will continue to price WBTC using the BTC/USD price, even though WBTC will instantly become worth far less than native BTC due to the bridge compromise.

Users could then buy WBTC for a far lower value than native BTC, deposit it into the protocol, and borrow against it using the value of native BTC. This would allow attackers to drain the protocol in the event of a bridge compromise leading to a depeg event.

**Suggestion**

the protocol could use Chainlink’s WBTC/BTC price feed to monitor for a depeg event.

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
