---
id: chainlink__chainlink_oracle_price_updates_can_be_front_run
name: "Chainlink-Oracle Price Updates Can Be Front-Run"
source_workflow: chainlink
upstream_model: gpt-4o-mini
tags: ["Chainlink", "Oracle", "Bad Randomness"]
routing_hints: []
prompt_chars: 1752
---

# Chainlink-Oracle Price Updates Can Be Front-Run

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Oracle Price Updates Can Be Front-Run**
Some stablecoin protocols that allow users to deposit collateral and mint/burn stablecoin tokens based upon prices of collateral assets can be subject to having value extracted from the protocol by having their oracle updates sandwich attacked.

Oracle price updates may be too slow behind real-world prices due to only updating after a set deviation % of price change, plus attackers may see oracle updates in the mempool & front-run them. 

**Suggestion**

This is a complicated problem to solve; potential solutions involve:

1.adding a small fee to mint/burn operations to make the frequent minting/burning which occurs in sandwich attacks less profitable
2.when a user makes a deposit, enforce a delay that prevents them from withdrawing in a short amount of time to prevent sandwich attacks

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
