---
id: chainlink__chainlink_re_requesting_randomness
name: "Chainlink-Re-requesting Randomness"
source_workflow: chainlink
upstream_model: gpt-4o-mini
tags: ["Chainlink", "Oracle", "Bad Randomness"]
routing_hints: []
prompt_chars: 1727
---

# Chainlink-Re-requesting Randomness

## Detection prompt

You are a smart contract auditor. After reading the following vulnerability knowledge and understanding correct and incorrect examples, detect the problem in the contract code.

### Vulnerability Knowledge

**Re-requesting Randomness**
If a smart contract allows re-requesting randomness, a VRF service provider could exploit this feature. When the initially returned random number is unfavorable to a certain party, the provider might delay or reject the first request and subsequently re-request a more favorable random result, thereby manipulating the final outcome.

This behavior could compromise true randomness, affecting outcomes, fairness, or other decisions that rely on the randomness mechanism.

**Suggestion**

Restrict the ability to re-request randomness and ensure there is no interaction between the requester and the service provider that could allow manipulation of the returned random number. When necessary, refer to the latest Chainlink VRF security best practices to implement mitigation measures.

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
