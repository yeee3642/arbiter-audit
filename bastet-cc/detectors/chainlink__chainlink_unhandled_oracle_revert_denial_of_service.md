---
id: chainlink__chainlink_unhandled_oracle_revert_denial_of_service
name: "Chainlink-Unhandled Oracle Revert Denial Of Service"
source_workflow: chainlink
upstream_model: gpt-4o-mini
tags: ["DoS"]
routing_hints: []
prompt_chars: 2014
---

# Chainlink-Unhandled Oracle Revert Denial Of Service

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Unhandled Oracle Revert Denial Of Service**
Calls to Oracles could potentially revert, which may result in a complete Denial-of-Service to smart contracts which depend upon them. Chainlink multisigs can immediately block access to price feeds at will, so just because a price feed is working today does not mean it will continue to do so indefinitely.

**Suggestion**

Smart contracts should handle "Unhandled Oracle Revert Denial Of Service" by:

wrapping calls to Oracles in try/catch blocks and dealing appropriately with any errors,
providing functionality to replace or update oracle feeds after they are configured.
If a configured Oracle feed has malfunctioned or ceased operating, but the smart contract does not have any alternative data source, nor does the contract allow updates to data sources, that contract will be permanently bricked.

This would be especially bad for stablecoin protocols and lending/borrowing platforms where large amounts of user value are stored in the form of collateral that would no longer be able to be withdrawn due to calls to the price oracles reverting.

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
