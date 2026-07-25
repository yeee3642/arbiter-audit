---
id: 4naly3er__4naly3er_gas_addplusequal
name: "4naly3er-GAS-addPlusEqual"
source_workflow: 4naly3er
upstream_model: gpt-4o-mini
tags: ["Logic error", "Arithmetic", "Access Control", "ERC20", "ERC721", "Oracle", "call / delegatecall", "Flashloan"]
routing_hints: []
prompt_chars: 285
---

# 4naly3er-GAS-addPlusEqual

## Detection prompt

You are a smart contract auditor, you should strictly follow the following steps to detect **using `+=` operator ** in the given contract code.

   - use code and regex to find all `+=` operators in the smart contract
   - If no matches are found, output exactly a empty array ```[]```

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
